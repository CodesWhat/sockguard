import { Activity, Fingerprint, Key, Layers, Shield, Users2 } from "lucide-react";
import type { ComparisonRouteRawConfig } from "@/lib/comparison-route-data/types";

export const wollomaticComparisonRouteData = {
  slug: "wollomatic",
  comparisonTable: `
Method + path filtering|Yes (regex)|Yes|tie
Upstream watchdog|Yes|Yes (+ /health endpoint + metrics)|tie
Structured logging|Yes (JSON option)|Yes (request + W3C trace correlation)|tie
Bind-mount restriction|Yes (body inspection)|No separate feature — covered by body inspection|competitor
Config simplicity|ENV vars, no file needed|YAML config required|competitor
Request body inspection (full)|Partial (bind mounts only)|Yes (12+ resource types)|self
Per-client policies|Partial (IP/hostname + labels)|Full (CIDR + labels + cert selectors + SPKI + unix peer)|self
Signed policy bundles|No|Yes (cosign keyed + keyless, Rekor)|self
Container image trust|No|Yes (cosign + enforce / warn modes)|self
Prometheus metrics|No|Yes (socket-proxy request metrics)|self
Rollout modes (enforce / warn / audit)|No|Yes (per-profile shadow mode)|self
Rate limits|No|Yes (per-profile token-bucket)|self
Audit log schema|No|Yes (JSON schema + reason codes)|self
`,
  highlightsTable: `
shield|Full Request Body Inspection|wollomatic can restrict bind mounts in request bodies. Sockguard goes further — inspecting container create, exec, image pull, volume, network, secret, config, service, swarm, node, and plugin requests for fine-grained control.
users|Full Per-Client Policies|wollomatic supports IP/hostname and label-based client matching. Sockguard adds TLS certificate selectors (including SPKI pinning), unix peer credentials, and CIDR ranges — each profile carrying its own independent ruleset.
key|Signed Policy Bundles|Sockguard verifies policy files with cosign keyed or keyless signatures and Rekor inclusion. wollomatic has no policy signing — anyone who can write the config file can change the rules.
fingerprint|Container Image Trust|Sockguard enforces image signatures at run time — blocking exec or create calls for images that aren't signed or don't match a trusted digest. wollomatic has no image-trust layer.
activity|Prometheus Metrics|Sockguard exports socket-proxy request metrics, deny counts, and latency histograms. wollomatic has JSON logs but no metrics endpoint.
layers|Rollout Modes|Sockguard's per-profile rollout modes (enforce / warn / audit) let you shadow-test strict rules before they block anything. wollomatic is enforce-only.
`,
  highlightIconMap: {
    shield: Shield,
    users: Users2,
    key: Key,
    fingerprint: Fingerprint,
    activity: Activity,
    layers: Layers,
  },
  metadataTitle: "wollomatic socket-proxy vs Sockguard — Docker Socket Proxy Comparison",
  metadataDescription:
    "Compare wollomatic socket-proxy and Sockguard. wollomatic ships regex path rules, bind-mount restrictions, and an upstream watchdog — see how Sockguard adds full body inspection, per-client cert selectors, signed bundles, and Prometheus metrics.",
  metadataKeywords: [
    "wollomatic socket-proxy vs sockguard",
    "wollomatic alternative",
    "wollomatic docker socket proxy alternative",
    "docker socket proxy regex rules",
    "docker socket proxy body inspection",
    "docker socket proxy per-client policy",
  ],
  openGraphDescription:
    "wollomatic ships regex rules, bind-mount restrictions, and a watchdog. See how Sockguard adds full body inspection, cert selectors, signed bundles, and Prometheus metrics.",
  twitterDescription: "Compare wollomatic socket-proxy and Sockguard for Docker socket filtering.",
  competitorName: "wollomatic",
  heroTitle: "wollomatic vs Sockguard",
  heroDescription: (
    <p>
      wollomatic&apos;s socket-proxy ships regex path rules, bind-mount restrictions, and an
      upstream watchdog — genuinely useful additions over the ENV-var baseline. Sockguard builds on
      the same ideas and goes further:{" "}
      <strong className="text-neutral-900 dark:text-neutral-200">
        full request body inspection across 12+ resource types, per-client certificate selectors,
        signed policy bundles, and Prometheus metrics
      </strong>
      .
    </p>
  ),
  migrationTitle: "Coming from wollomatic?",
  migrationDescription:
    "Your regex path rules translate directly to Sockguard YAML rule blocks. Body inspection rules replace the bind-mount filter with full coverage. The upstream watchdog is built in — and you get a /health endpoint and Prometheus metrics on top.",
  jsonLdName: "wollomatic socket-proxy vs Sockguard — Docker Socket Proxy Comparison",
  jsonLdDescription: "Compare wollomatic socket-proxy and Sockguard for Docker socket filtering.",
} satisfies ComparisonRouteRawConfig;
