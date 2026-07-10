import { Activity, Fingerprint, Key, Layers, Shield, Users2 } from "lucide-react";
import type { ComparisonRouteRawConfig } from "@/lib/comparison-route-data/types";

export const cetusguardComparisonRouteData = {
  slug: "cetusguard",
  comparisonTable: `
Method + path filtering|Yes (regex)|Yes|tie
Remote TCP mTLS listener|Yes|Yes (TLS 1.3)|tie
Regex path rules|Yes|Yes|tie
Remote daemon upstream (TLS)|Yes (in production)|Yes (active/passive failover)|self
Config simplicity|Compact rule files|Full YAML config|competitor
Request body inspection|No|Yes (12+ resource types)|self
Per-client policies|No|CIDR + labels + cert selectors + SPKI + unix peer|self
Read-side redaction|No|Yes (visibility rules + JSON field redaction)|self
Signed policy bundles|No|Yes (cosign keyed + keyless, Rekor)|self
Container image trust|No|Yes (cosign + enforce / warn modes)|self
Prometheus metrics|No|Yes (socket-proxy request metrics)|self
Rate limits|No|Yes (per-profile token-bucket)|self
Rollout modes (enforce / warn / audit)|No|Yes (per-profile shadow mode)|self
Audit log schema|No|Yes (JSON schema + reason codes)|self
`,
  highlightsTable: `
shield|Request Body Inspection|CetusGuard filters by method and path only. Sockguard inspects request bodies — blocking containers by image, exec commands by pattern, bind mounts by path, and more across 12+ resource types.
users|Per-Client Policies|CetusGuard applies the same regex rules to every caller. Sockguard assigns different policies per CIDR range, Docker label, TLS certificate selector (including SPKI pinning), or Unix peer credential.
key|Signed Policy Bundles|Sockguard verifies policy files with cosign keyed or keyless signatures and Rekor transparency log inclusion. An unsigned or tampered bundle is rejected before any request is evaluated.
fingerprint|Container Image Trust|Sockguard enforces image signatures at run time — blocking create or exec calls for images that aren't signed or don't match a trusted digest. CetusGuard has no image-trust layer.
activity|Prometheus Metrics|Sockguard exports socket-proxy request metrics, deny counts, and latency histograms. CetusGuard has no built-in metrics endpoint.
layers|Rollout Modes|Sockguard's per-profile rollout modes (enforce / warn / audit) let you shadow-test strict rules before they block anything. CetusGuard is enforce-only.
`,
  highlightIconMap: {
    shield: Shield,
    users: Users2,
    key: Key,
    fingerprint: Fingerprint,
    activity: Activity,
    layers: Layers,
  },
  metadataTitle: "CetusGuard vs Sockguard — Docker Socket Proxy Comparison",
  metadataDescription:
    "Compare CetusGuard and Sockguard. CetusGuard pioneered regex-based Docker socket filtering with two-way mTLS — see how Sockguard adds request body inspection, per-client policies, signed bundles, and Prometheus metrics.",
  metadataKeywords: [
    "cetusguard vs sockguard",
    "cetusguard alternative",
    "cetusguard replacement",
    "docker socket proxy mtls comparison",
    "docker socket proxy regex rules",
    "docker socket proxy body inspection",
    "docker socket proxy signed policies",
  ],
  openGraphDescription:
    "CetusGuard pioneered regex-based filtering with two-way mTLS. See how Sockguard adds body inspection, per-client policies, signed bundles, and Prometheus metrics.",
  twitterDescription: "Compare CetusGuard and Sockguard for Docker socket filtering.",
  competitorName: "CetusGuard",
  heroTitle: "CetusGuard vs Sockguard",
  heroDescription: (
    <p>
      CetusGuard pioneered regex-based Docker socket filtering with two-way mTLS — a genuinely
      stronger security baseline than ENV-var proxies. Sockguard matches the mTLS listener and adds{" "}
      <strong className="text-neutral-900 dark:text-neutral-200">
        request body inspection, per-client certificate selectors, signed policy bundles, and
        Prometheus metrics
      </strong>
      . Sockguard now ships remote daemon TLS too — with health-checked active/passive failover
      across redundant endpoints, which CetusGuard doesn't have.
    </p>
  ),
  migrationTitle: "Coming from CetusGuard?",
  migrationDescription:
    "Your regex path rules translate directly to Sockguard YAML rule blocks, and your mTLS certificates work unchanged. Sockguard exposes the same TCP listener — swap the image and enable body inspection and per-client profiles at your own pace.",
  jsonLdName: "CetusGuard vs Sockguard — Docker Socket Proxy Comparison",
  jsonLdDescription: "Compare CetusGuard and Sockguard for Docker socket filtering.",
} satisfies ComparisonRouteRawConfig;
