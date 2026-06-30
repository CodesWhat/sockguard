import { Activity, Eye, Key, Layers, Shield, Users2 } from "lucide-react";
import type { ComparisonRouteRawConfig } from "@/lib/comparison-route-data/types";

export const linuxserverComparisonRouteData = {
  slug: "linuxserver",
  comparisonTable: `
Method + path filtering|Yes|Yes|tie
Config format|ENV vars (Tecnativa-compatible)|YAML config|competitor
LSIO ecosystem|Full s6-overlay + LSIO packaging|Standard Docker image|competitor
Community backing|LinuxServer.io (100k+ users)|CodesWhat|competitor
Request body inspection|No|Yes (12+ resource types)|self
Per-client policies|No|CIDR + labels + cert selectors + unix peer|self
Prometheus metrics|No|Yes (socket-proxy request metrics)|self
Signed policy bundles|No|Yes (cosign keyed + keyless, Rekor)|self
Rollout modes (enforce / warn / audit)|No|Yes (per-profile shadow mode)|self
Rate limits|No|Yes (per-profile token-bucket)|self
Hot-reload|No|Yes (SIGHUP/fsnotify, validate endpoint)|self
Audit log schema|No|Yes (JSON schema + reason codes)|self
`,
  highlightsTable: `
shield|Request Body Inspection|LinuxServer filters by method and path only. Sockguard inspects request bodies — blocking containers by image, exec commands by pattern, bind mounts by path, and more across 12+ resource types.
users|Per-Client Policies|LinuxServer applies the same ENV-var rules to every caller. Sockguard assigns different policies per CIDR range, Docker label, TLS certificate selector, or Unix peer — so CI, monitoring, and admin clients can each have a tighter scope.
key|Signed Policy Bundles|Sockguard verifies policy files with cosign keyed or keyless signatures and Rekor transparency log inclusion. An unsigned or tampered bundle is rejected before any request reaches the daemon.
activity|Prometheus Metrics|Sockguard exports socket-proxy request metrics, deny counts, and latency histograms. LinuxServer has no built-in observability beyond container logs.
layers|Rollout Modes|Sockguard's per-profile rollout modes (enforce / warn / audit) let you shadow-test a new policy before it blocks anything. Roll out strict rules without a maintenance window.
eye|Read-Side Redaction|Sockguard can redact sensitive fields from GET responses — labels, environment variables, mount paths — so callers only see what their policy allows. LinuxServer has no response filtering.
`,
  highlightIconMap: {
    shield: Shield,
    users: Users2,
    key: Key,
    activity: Activity,
    layers: Layers,
    eye: Eye,
  },
  metadataTitle: "LinuxServer docker-socket-proxy vs Sockguard — Docker Socket Proxy Comparison",
  metadataDescription:
    "Compare LinuxServer docker-socket-proxy and Sockguard. LinuxServer brings LSIO packaging to Tecnativa's ENV-based approach — see how Sockguard adds body inspection, per-client policies, signed bundles, and Prometheus metrics.",
  metadataKeywords: [
    "linuxserver docker-socket-proxy vs sockguard",
    "linuxserver alternative",
    "linuxserver docker socket proxy alternative",
    "lsio docker-socket-proxy replacement",
    "docker socket proxy body inspection",
    "docker socket proxy signed policies",
  ],
  openGraphDescription:
    "LinuxServer brings LSIO packaging to the Tecnativa approach. See how Sockguard adds body inspection, per-client policies, signed bundles, and Prometheus metrics.",
  twitterDescription:
    "Compare LinuxServer docker-socket-proxy and Sockguard for Docker socket filtering.",
  competitorName: "LinuxServer",
  heroTitle: "LinuxServer vs Sockguard",
  heroDescription: (
    <p>
      LinuxServer&apos;s docker-socket-proxy brings the LSIO ecosystem and community maintenance to
      Tecnativa&apos;s proven ENV-var approach. Sockguard matches the drop-in simplicity and adds{" "}
      <strong className="text-neutral-900 dark:text-neutral-200">
        request body inspection, per-client policies, signed policy bundles, and Prometheus metrics
      </strong>{" "}
      — all in a lean Go binary with no s6-overlay required.
    </p>
  ),
  migrationTitle: "Coming from LinuxServer?",
  migrationDescription:
    "Translate your ENV var allow-list to Sockguard YAML rules once. Sockguard mounts the same socket, speaks the same Docker API, and drops into your compose stack as a one-line service swap — then you can enable body inspection and per-client profiles at your own pace.",
  jsonLdName: "LinuxServer docker-socket-proxy vs Sockguard — Docker Socket Proxy Comparison",
  jsonLdDescription:
    "Compare LinuxServer docker-socket-proxy and Sockguard for Docker socket filtering.",
} satisfies ComparisonRouteRawConfig;
