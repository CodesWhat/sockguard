import {
  ArrowRight,
  BookOpen,
  Check,
  Clock,
  FileText,
  Minus,
  Shield,
  ShieldCheck,
  SlidersHorizontal,
  Terminal,
  Zap,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

type FeatureCategory = "security" | "control" | "operations";

const categoryLabels: Record<FeatureCategory, { label: string; color: string; border: string }> = {
  security: {
    label: "Security",
    color: "text-rose-600 dark:text-rose-400",
    border: "border-rose-500/30",
  },
  control: {
    label: "Control",
    color: "text-blue-600 dark:text-blue-400",
    border: "border-blue-500/30",
  },
  operations: {
    label: "Operations",
    color: "text-emerald-600 dark:text-emerald-400",
    border: "border-emerald-500/30",
  },
};

const features: {
  icon: typeof Shield;
  title: string;
  color: string;
  bg: string;
  description: string;
  category: FeatureCategory;
}[] = [
  {
    icon: ShieldCheck,
    title: "Default-Deny Posture",
    color: "text-rose-500 dark:text-rose-400",
    bg: "bg-rose-100 dark:bg-rose-900/50",
    description: "Everything blocked unless explicitly allowed. No match means deny.",
    category: "security",
  },
  {
    icon: SlidersHorizontal,
    title: "Granular Control",
    color: "text-blue-500 dark:text-blue-400",
    bg: "bg-blue-100 dark:bg-blue-900/50",
    description:
      "Allow start/stop while blocking create/exec. Per-operation POST controls with glob matching.",
    category: "control",
  },
  {
    icon: Zap,
    title: "Structured Logging",
    color: "text-emerald-500 dark:text-emerald-400",
    bg: "bg-emerald-100 dark:bg-emerald-900/50",
    description:
      "JSON access logs with method, path, decision, matched rule index, latency, and client info.",
    category: "operations",
  },
  {
    icon: FileText,
    title: "YAML Configuration",
    color: "text-blue-500 dark:text-blue-400",
    bg: "bg-blue-100 dark:bg-blue-900/50",
    description:
      "Declarative rules in YAML. Glob patterns for paths, first-match-wins evaluation, 10 bundled presets.",
    category: "control",
  },
  {
    icon: ArrowRight,
    title: "Tecnativa Compatible",
    color: "text-emerald-500 dark:text-emerald-400",
    bg: "bg-emerald-100 dark:bg-emerald-900/50",
    description:
      "Drop-in replacement using the same env vars. CONTAINERS=1, POST=0, ALLOW_START=1 all work.",
    category: "operations",
  },
  {
    icon: Shield,
    title: "Minimal Attack Surface",
    color: "text-rose-500 dark:text-rose-400",
    bg: "bg-rose-100 dark:bg-rose-900/50",
    description:
      "Wolfi-based image, ~12MB, near-zero CVEs. Cosign-signed with SBOM and build provenance.",
    category: "security",
  },
];

const comparisonRows: {
  feature: string;
  tecnativa: string;
  linuxserver: string;
  wollomatic: string;
  sockguard: string;
  planned?: boolean;
}[] = [
  {
    feature: "Method + path filtering",
    tecnativa: "Yes",
    linuxserver: "Yes",
    wollomatic: "Yes",
    sockguard: "Yes",
  },
  {
    feature: "Granular POST ops",
    tecnativa: "No",
    linuxserver: "Partial",
    wollomatic: "Via regex",
    sockguard: "Yes",
  },
  {
    feature: "Request body inspection",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "No",
    sockguard: "Planned",
    planned: true,
  },
  {
    feature: "Per-client policies",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "IP only",
    sockguard: "Planned",
    planned: true,
  },
  {
    feature: "Response filtering",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "No",
    sockguard: "Planned",
    planned: true,
  },
  {
    feature: "Structured audit log",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "No",
    sockguard: "Yes",
  },
  {
    feature: "YAML config",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "No",
    sockguard: "Yes",
  },
];

const dockerCompose = `services:
  sockguard:
    image: codeswhat/sockguard:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - sockguard-socket:/var/run/sockguard
    environment:
      - CONTAINERS=1
      - EVENTS=1

  your-app:
    depends_on:
      - sockguard
    volumes:
      - sockguard-socket:/var/run/sockguard:ro

volumes:
  sockguard-socket:`;

function ComparisonCell({ value, planned }: { value: string; planned?: boolean }) {
  if (planned) {
    return (
      <Badge
        variant="outline"
        className="border-amber-500/30 text-amber-600 dark:text-amber-400"
      >
        <Clock className="size-3" />
        {value}
      </Badge>
    );
  }
  if (value === "Yes") {
    return (
      <span className="inline-flex items-center gap-1 text-emerald-600 dark:text-emerald-400">
        <Check className="size-4" />
        Yes
      </span>
    );
  }
  if (value === "No") {
    return (
      <span className="inline-flex items-center gap-1 text-neutral-400 dark:text-neutral-600">
        <Minus className="size-4" />
        No
      </span>
    );
  }
  return <span className="text-neutral-600 dark:text-neutral-400">{value}</span>;
}

export default function Home() {
  return (
    <main className="relative min-h-screen bg-gradient-to-br from-neutral-50 to-neutral-100 dark:from-neutral-950 dark:to-neutral-900">
      {/* Background Pattern */}
      <div className="bg-grid-neutral-200/50 dark:bg-grid-neutral-800/50 fixed inset-0" />

      <div className="relative z-10">
        {/* Hero Section */}
        <section className="relative flex min-h-[80vh] flex-col items-center justify-center px-4 py-20">
          <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_center,_white_20%,_transparent_70%)] dark:bg-[radial-gradient(ellipse_at_center,_rgb(10,10,10)_20%,_transparent_70%)]" />

          <div className="relative z-10 flex flex-col items-center">
            <Badge variant="secondary" className="mb-6 px-4 py-1.5 text-sm font-medium">
              Open Source &middot; AGPL-3.0
            </Badge>

            <div className="max-w-4xl text-center">
              <h1 className="mb-4 text-5xl font-bold tracking-tight text-neutral-900 dark:text-neutral-100 sm:text-6xl lg:text-7xl">
                Docker Socket
                <br />
                <span className="text-neutral-600 dark:text-neutral-400">Proxy</span>
              </h1>

              <p className="mx-auto mb-10 max-w-2xl text-lg text-neutral-600 sm:text-xl dark:text-neutral-400">
                Guide what gets through. Filter Docker API requests by method and path with
                default-deny posture, structured audit logging, and drop-in Tecnativa
                compatibility.
              </p>

              <div className="flex flex-col items-center justify-center gap-4 sm:flex-row">
                <Button size="lg" asChild>
                  <a
                    href="https://github.com/CodesWhat/sockguard"
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    <svg className="h-4 w-4" viewBox="0 0 24 24" fill="currentColor">
                      <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
                    </svg>
                    View on GitHub
                  </a>
                </Button>
                <Button variant="outline" size="lg" asChild>
                  <a href="https://docs.getsockguard.com">
                    <BookOpen className="h-4 w-4" />
                    Documentation
                  </a>
                </Button>
              </div>
            </div>
          </div>
        </section>

        {/* Features Section */}
        <section className="px-4 py-24">
          <div className="mx-auto max-w-5xl">
            <div className="relative mb-16 text-center">
              <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_center,_white_20%,_transparent_50%)] dark:bg-[radial-gradient(ellipse_at_center,_rgb(10,10,10)_20%,_transparent_50%)]" />
              <h2 className="relative text-3xl font-bold tracking-tight text-neutral-900 sm:text-4xl dark:text-neutral-50">
                Features
              </h2>
              <p className="relative mt-4 text-neutral-600 dark:text-neutral-400">
                Security-first Docker socket proxy with zero external dependencies
              </p>
            </div>

            <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
              {features.map((feature) => {
                const cat = categoryLabels[feature.category];
                return (
                  <div
                    key={feature.title}
                    className="rounded-xl border border-neutral-200 bg-white/50 p-6 backdrop-blur-sm transition-colors hover:bg-white/80 dark:border-neutral-800 dark:bg-neutral-900/50 dark:hover:bg-neutral-900/80"
                  >
                    <div className="mb-4 flex items-start justify-between">
                      <div
                        className={`flex h-10 w-10 items-center justify-center rounded-lg ${feature.bg}`}
                      >
                        <feature.icon className={`h-5 w-5 ${feature.color}`} />
                      </div>
                      <Badge variant="outline" className={`${cat.border} ${cat.color}`}>
                        {cat.label}
                      </Badge>
                    </div>
                    <h3 className="mb-2 font-semibold text-neutral-900 dark:text-neutral-50">
                      {feature.title}
                    </h3>
                    <p className="text-sm text-neutral-600 dark:text-neutral-400">
                      {feature.description}
                    </p>
                  </div>
                );
              })}
            </div>
          </div>
        </section>

        {/* Quick Start Section */}
        <section className="px-4 py-24">
          <div className="mx-auto max-w-3xl">
            <div className="relative mb-16 text-center">
              <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_center,_white_20%,_transparent_50%)] dark:bg-[radial-gradient(ellipse_at_center,_rgb(10,10,10)_20%,_transparent_50%)]" />
              <h2 className="relative text-3xl font-bold tracking-tight text-neutral-900 sm:text-4xl dark:text-neutral-50">
                Quick Start
              </h2>
              <p className="relative mt-4 text-neutral-600 dark:text-neutral-400">
                Add to your docker-compose.yml and you&apos;re done
              </p>
            </div>

            <div className="overflow-hidden rounded-xl border border-neutral-800 bg-neutral-950 shadow-2xl">
              <div className="flex items-center gap-2 border-b border-neutral-800 px-4 py-3">
                <Terminal className="h-4 w-4 text-neutral-500" />
                <span className="text-xs font-medium text-neutral-500">docker-compose.yml</span>
              </div>
              <pre className="overflow-x-auto p-6 font-[family-name:var(--font-mono)] text-sm leading-relaxed text-neutral-300">
                {dockerCompose}
              </pre>
            </div>
          </div>
        </section>

        {/* Comparison Section */}
        <section className="px-4 py-24">
          <div className="mx-auto max-w-5xl">
            <div className="relative mb-16 text-center">
              <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_center,_white_20%,_transparent_50%)] dark:bg-[radial-gradient(ellipse_at_center,_rgb(10,10,10)_20%,_transparent_50%)]" />
              <h2 className="relative text-3xl font-bold tracking-tight text-neutral-900 sm:text-4xl dark:text-neutral-50">
                Comparison
              </h2>
              <p className="relative mt-4 text-neutral-600 dark:text-neutral-400">
                How Sockguard stacks up against other Docker socket proxies
              </p>
            </div>

            <div className="overflow-x-auto rounded-xl border border-neutral-200 bg-white/50 backdrop-blur-sm dark:border-neutral-800 dark:bg-neutral-900/50">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-neutral-200 dark:border-neutral-800">
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-neutral-500">
                      Feature
                    </th>
                    <th className="px-4 py-3 text-center text-xs font-semibold uppercase tracking-wider text-neutral-500">
                      Tecnativa
                    </th>
                    <th className="px-4 py-3 text-center text-xs font-semibold uppercase tracking-wider text-neutral-500">
                      LinuxServer
                    </th>
                    <th className="px-4 py-3 text-center text-xs font-semibold uppercase tracking-wider text-neutral-500">
                      wollomatic
                    </th>
                    <th className="px-4 py-3 text-center text-xs font-semibold uppercase tracking-wider text-neutral-900 dark:text-neutral-50">
                      Sockguard
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {comparisonRows.map((row) => (
                    <tr
                      key={row.feature}
                      className="border-b border-neutral-100 transition-colors hover:bg-neutral-50 last:border-0 dark:border-neutral-800/50 dark:hover:bg-neutral-900/50"
                    >
                      <td className="px-4 py-3 font-medium text-neutral-900 dark:text-neutral-100">
                        {row.feature}
                      </td>
                      <td className="px-4 py-3 text-center">
                        <ComparisonCell value={row.tecnativa} />
                      </td>
                      <td className="px-4 py-3 text-center">
                        <ComparisonCell value={row.linuxserver} />
                      </td>
                      <td className="px-4 py-3 text-center">
                        <ComparisonCell value={row.wollomatic} />
                      </td>
                      <td className="px-4 py-3 text-center">
                        <ComparisonCell value={row.sockguard} planned={row.planned} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </section>

        {/* Footer */}
        <footer className="border-t border-neutral-200 px-4 py-12 dark:border-neutral-800">
          <div className="mx-auto max-w-5xl text-center">
            <p className="text-sm text-neutral-500">
              Sockguard is open source under the{" "}
              <a
                href="https://github.com/CodesWhat/sockguard/blob/main/LICENSE"
                target="_blank"
                rel="noopener noreferrer"
                className="underline underline-offset-4 hover:text-neutral-900 dark:hover:text-neutral-100"
              >
                AGPL-3.0 license
              </a>
              . Built by{" "}
              <a
                href="https://codeswhat.com"
                target="_blank"
                rel="noopener noreferrer"
                className="underline underline-offset-4 hover:text-neutral-900 dark:hover:text-neutral-100"
              >
                CodesWhat
              </a>
              .
            </p>
          </div>
        </footer>
      </div>
    </main>
  );
}
