import { Activity, Key, Layers, Shield, Users2, Zap } from "lucide-react";
import type { ComparisonRouteRawConfig } from "@/lib/comparison-route-data/types";

export const tecnativaComparisonRouteData = {
  slug: "tecnativa",
  comparisonTable: `
Method + path filtering|Yes|Yes|tie
Config format|ENV vars (zero learning curve)|YAML config|competitor
Community size|Huge (50k+ GitHub stars)|Growing|competitor
Production maturity|10+ years in production|Newer|competitor
Request body inspection|No|Yes (12+ resource types)|self
Per-client policies|No|CIDR + labels + cert selectors + unix peer|self
Prometheus metrics|No|Yes (socket-proxy request metrics)|self
Signed policy bundles|No|Yes (cosign keyed + keyless, Rekor)|self
Rollout modes (enforce / warn / audit)|No|Yes (per-profile shadow mode)|self
Rate limits|No|Yes (per-profile token-bucket)|self
YAML config + hot-reload|No|Yes (SIGHUP/fsnotify, validate endpoint)|self
Audit log schema|No|Yes (JSON schema + reason codes)|self
`,
  highlightsTable: `
shield|Request Body Inspection|Tecnativa filters by method and path only. Sockguard goes into the request body — blocking containers by image, exec commands by pattern, bind mounts by path, and more across 12+ resource types.
users|Per-Client Policies|Every client sees the same rules with Tecnativa. Sockguard lets you assign different policies per CIDR range, Docker label, TLS certificate selector (including SPKI pinning), or Unix peer credential.
key|Signed Policy Bundles|Sockguard verifies policy files with cosign keyed or keyless signatures and Rekor transparency log inclusion. An unsigned or tampered bundle is rejected before any request is evaluated.
activity|Prometheus Metrics|Sockguard exports socket-proxy request metrics, deny counts, and latency histograms that plug directly into your existing Grafana dashboards. Tecnativa has no built-in metrics.
layers|Rollout Modes|Shadow-mode enforcement lets you ship new rules without breaking anything. Sockguard's per-profile rollout modes (enforce / warn / audit) mean you can test a policy before it goes live.
zap|Rate Limits|Sockguard's per-profile token-bucket rate limiter and global priority gate protect the daemon from runaway callers. Tecnativa has no request-rate controls.
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
      socket filtering — simple, battle-tested, trusted by tens of thousands of deployments.
      Sockguard builds on that foundation with{" "}
      <strong className="text-neutral-900 dark:text-neutral-200">
        request body inspection, per-client policies, signed policy bundles, and Prometheus metrics
      </strong>{" "}
      — without any SaaS layer.
    </p>
  ),
  migrationTitle: "Coming from Tecnativa?",
  migrationDescription:
    "Map your existing ENV var allow-list to Sockguard YAML rules once, then layer on body inspection, per-client profiles, and signed bundles. Sockguard runs on the same socket mount — no other infrastructure changes required.",
  jsonLdName: "Tecnativa docker-socket-proxy vs Sockguard — Docker Socket Proxy Comparison",
  jsonLdDescription:
    "Compare Tecnativa docker-socket-proxy and Sockguard for Docker socket filtering.",
} satisfies ComparisonRouteRawConfig;
