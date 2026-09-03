import { Activity, Key, Layers, Shield, Users2, Zap } from "lucide-react";
import type { ComparisonRouteRawConfig } from "@/lib/comparison-route-data/types";

export const tecnativaComparisonRouteData = {
  slug: "tecnativa",
  comparisonTable: `
Method + path filtering|Yes|Yes|tie
Config format|ENV vars (zero learning curve)|YAML config|competitor
Community size|2.6k+ GitHub stars|Growing|competitor
Production maturity|Maintained since 2017|Newer|competitor
Request body inspection|No|Yes (12+ resource types, Docker + Podman build)|self
Per-client policies|No|CIDR + labels + cert selectors + unix peer|self
Prometheus metrics|No|Yes (opt-in, finite-label socket-proxy metrics)|self
Signed policy bundles|No|Yes (separate pinned trust, keyed + keyless)|self
Rollout modes (enforce / warn / audit)|No|Yes (per-profile shadow mode)|self
Rate limits|No|Yes (per-profile token-bucket)|self
YAML config + hot-reload|No|Yes (opt-in, SIGHUP/fsnotify, validate endpoint)|self
Audit log schema|No|Yes (opt-in, JSON schema + reason codes)|self
`,
  highlightsTable: `
shield|Request Body Inspection|Tecnativa filters by method and path only. Sockguard inspects bodies across 12+ resource types, including Docker and native Podman builds, before the daemon receives them.
users|Per-Client Policies|Every client sees the same rules with Tecnativa. Sockguard lets you assign different policies per CIDR range, Docker label, TLS certificate selector (including SPKI pinning), or Unix peer credential.
key|Signed Policy Bundles|Sockguard pins keyed or keyless trust in a separate bootstrap file, then verifies the candidate and every reload. The candidate cannot disable its own gate or redefine who may sign.
activity|Prometheus Metrics|Sockguard exports request metrics, deny counts, and latency histograms with finite method and route labels. Tecnativa has no built-in metrics.
layers|Rollout Modes|Shadow-mode enforcement lets you ship new rules without breaking anything. Sockguard's per-profile rollout modes (enforce / warn / audit) mean you can test a policy before it goes live.
zap|Rate Limits|Sockguard's per-profile token-bucket rate limiter and global priority gate protect the daemon from runaway callers. Tecnativa has no request-rate controls.
activity|No Upstream Reliability Regressions|Tecnativa v0.5.0, the version compared here, has an open regression since 2026-07-30 where its HAProxy 3.2.4 to 3.4.2 bump hangs GET /version for the full 10-minute default timeout, breaking Traefik, docktail, and crowdsec discovery that polls it (tecnativa/docker-socket-proxy#180, still open). Sockguard's /version passthrough isn't affected by that upstream dependency bump.
`,
  highlightIconMap: {
    shield: Shield,
    users: Users2,
    key: Key,
    activity: Activity,
    layers: Layers,
    zap: Zap,
  },
  metadataTitle: "Tecnativa docker-socket-proxy vs Sockguard — Docker Socket Proxy Comparison",
  metadataDescription:
    "Compare Tecnativa docker-socket-proxy and Sockguard. Tecnativa filters by ENV-var allow-lists — see how Sockguard adds request body inspection, per-client policies, signed bundles, and Prometheus metrics.",
  metadataKeywords: [
    "tecnativa docker-socket-proxy vs sockguard",
    "tecnativa alternative",
    "docker-socket-proxy alternative",
    "docker-socket-proxy replacement",
    "tecnativa docker socket proxy comparison",
    "docker socket proxy body inspection",
    "docker socket proxy per-client policy",
  ],
  openGraphDescription:
    "Tecnativa filters by ENV-var allow-lists. See how Sockguard adds request body inspection, per-client policies, signed bundles, and Prometheus metrics.",
  twitterDescription:
    "Compare Tecnativa docker-socket-proxy and Sockguard for Docker socket filtering.",
  competitorName: "Tecnativa",
  heroTitle: "Tecnativa vs Sockguard",
  heroDescription: (
    <p>
      Tecnativa&apos;s docker-socket-proxy is the community reference for ENV-var-based Docker
      socket filtering — simple, battle-tested, and backed by the largest established community in
      this category. Sockguard builds on that foundation with{" "}
      <strong className="text-neutral-900 dark:text-neutral-200">
        request body inspection, per-client policies, signed policy bundles, and Prometheus metrics
      </strong>{" "}
      — without any SaaS layer.
    </p>
  ),
  migrationTitle: "Coming from Tecnativa?",
  migrationDescription:
    "Start with the compatible ENV allow-list, plus SOCKGUARD_INSECURE_ALLOW_READ_EXFILTRATION=true — a broad section grant such as CONTAINERS=1 covers the archive, export, log and attach endpoints, and Sockguard fails startup rather than open them without an acknowledgment. Then map it to YAML before enabling signed policies, and drop the acknowledgment once the rules no longer need it. Signed mode rejects rule-generating compatibility variables so unsigned process state cannot modify verified rules. The socket mount stays the same.",
  jsonLdName: "Tecnativa docker-socket-proxy vs Sockguard — Docker Socket Proxy Comparison",
  jsonLdDescription:
    "Compare Tecnativa docker-socket-proxy and Sockguard for Docker socket filtering.",
} satisfies ComparisonRouteRawConfig;
