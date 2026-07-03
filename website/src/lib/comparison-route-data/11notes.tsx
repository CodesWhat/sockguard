import { Activity, Eye, Fingerprint, Key, Shield, Users2 } from "lucide-react";
import type { ComparisonRouteRawConfig } from "@/lib/comparison-route-data/types";

export const elevenNotesComparisonRouteData = {
  slug: "11notes",
  comparisonTable: `
Method filtering|Yes|Yes|tie
Read-only focus|Yes (hardcoded, zero write risk)|Configurable (read + controlled write)|competitor
Zero-config|Yes (no file needed)|No (YAML required)|competitor
Attack surface|Minimal (read-only hardcoded)|Broader (configurable)|competitor
Request body inspection|No|Yes (12+ resource types)|self
Per-client policies|No|CIDR + labels + cert selectors + unix peer|self
Write API control|No (blocks all writes)|Yes (default-deny + granular rules)|self
Read-side redaction|Partial (7 risky GETs blocked)|Full (visibility rules + JSON field redaction)|self
Signed policy bundles|No|Yes (cosign keyed + keyless, Rekor)|self
Container image trust|No|Yes (cosign + enforce / warn modes)|self
Prometheus metrics|No|Yes (socket-proxy request metrics)|self
Rate limits|No|Yes (per-profile token-bucket)|self
Audit log schema|No|Yes (JSON schema + reason codes)|self
`,
  highlightsTable: `
shield|Configurable Default-Deny|11notes is read-only by design — you cannot enable writes. Sockguard starts default-deny and lets you open exactly the operations you need with explicit rules, so CI can run containers while monitoring only reads metrics.
eye|Full Read-Side Redaction|11notes blocks 7 risky GET endpoints. Sockguard goes further with visibility rules and JSON field redaction — callers only see the labels, environment variables, and mount paths their policy allows.
users|Per-Client Policies|11notes applies the same read-only stance to every caller. Sockguard assigns different policies per CIDR range, Docker label, TLS certificate selector, or Unix peer credential.
fingerprint|Container Image Trust|Sockguard enforces image signatures at run time — blocking create or exec calls for images that aren't signed or don't match a trusted digest. 11notes has no image-trust layer.
key|Signed Policy Bundles|Sockguard verifies policy files with cosign keyed or keyless signatures and Rekor inclusion. Policy tampering is caught before any request is evaluated.
activity|Prometheus Metrics|Sockguard exports socket-proxy request metrics, deny counts, and latency histograms. 11notes has no observability layer beyond container logs.
`,
  highlightIconMap: {
    shield: Shield,
    eye: Eye,
    users: Users2,
    fingerprint: Fingerprint,
    key: Key,
    activity: Activity,
  },
  metadataTitle: "11notes docker-socket-proxy vs Sockguard — Docker Socket Proxy Comparison",
  metadataDescription:
    "Compare 11notes docker-socket-proxy and Sockguard. 11notes takes a minimal read-only stance with zero config — see how Sockguard gives you the same default-deny posture with configurable rules, per-client policies, and signed bundles.",
  metadataKeywords: [
    "11notes docker-socket-proxy vs sockguard",
    "11notes alternative",
    "11notes docker socket proxy alternative",
    "docker socket proxy read-only alternative",
    "docker socket proxy default-deny",
    "docker socket proxy minimal",
  ],
  openGraphDescription:
    "11notes takes a minimal zero-config read-only stance. See how Sockguard gives you the same default-deny posture with configurable rules, per-client policies, and signed bundles.",
  twitterDescription:
    "Compare 11notes docker-socket-proxy and Sockguard for Docker socket filtering.",
  competitorName: "11notes",
  heroTitle: "11notes vs Sockguard",
  heroDescription: (
    <p>
      11notes takes the most opinionated approach to socket security: read-only, no config, no write
      risk. Sockguard gives you the same{" "}
      <strong className="text-neutral-900 dark:text-neutral-200">default-deny posture</strong> and
      extends it to the full Docker API — with configurable rules, per-client policies, signed
      bundles, and image trust verification — so you can scope exactly what each caller is allowed
      to do.
    </p>
  ),
  migrationTitle: "Coming from 11notes?",
  migrationDescription:
    "Sockguard can replace 11notes entirely. Start with a read-only policy that mirrors 11notes' blocked endpoints, then gradually open write operations with explicit rules scoped to trusted clients. The default-deny baseline is identical — you just get more control.",
  jsonLdName: "11notes docker-socket-proxy vs Sockguard — Docker Socket Proxy Comparison",
  jsonLdDescription:
    "Compare 11notes docker-socket-proxy and Sockguard for Docker socket filtering.",
} satisfies ComparisonRouteRawConfig;
