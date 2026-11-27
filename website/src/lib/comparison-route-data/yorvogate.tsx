import type { ComparisonRouteRawConfig } from "@/lib/comparison-route-data/types";

export const yorvogateComparisonRouteData = {
  slug: "yorvogate",
  comparisonTable: `
Method + path filtering|Yes (endpoint groups on trusted listeners, per-endpoint rules per scope)|Yes|tie
Request body inspection|Yes (bodies decoded into the Docker Engine's own types, unknown fields refused)|Yes (12+ resource types)|tie
Query-string rule matching|Yes (per-endpoint query parameter allowlist, any other refused)|Yes (next v3.2, per-key match.query)|tie
Per-client policies|Yes (scopes by token, client certificate or own socket, optional peer user)|Yes (CIDR + labels + cert selectors incl. SPKI + unix peer)|tie
Resource owner labels|Yes (per-scope owner label and name prefixes)|Yes (workload + control plane)|tie
Remote TCP mTLS (listener)|Yes (TLS 1.3, mTLS required off loopback)|Yes (TLS 1.3)|tie
Remote daemon upstream (TLS)|No (upstream must be a unix socket)|Yes (active/passive failover)|self
Read-side visibility / redaction|Partial (lists limited to the scope's own objects; info and version are allow-lists)|Yes (visibility rules + JSON field redaction)|self
Prometheus metrics|Yes (admin listener, loopback or unix socket)|Yes (opt-in, socket-proxy request metrics)|tie
Rate limits / concurrency caps|Partial (per-scope request and connection caps)|Yes (per-profile token-bucket)|self
Rollout modes (enforce / warn / audit)|No (none documented at v0.4.0)|Yes (per-profile shadow mode)|self
Signed policy bundles|No (releases are cosign-signed, policy bundles are not documented)|Yes (cosign keyed + keyless, Rekor)|self
Container image trust|Partial (pull registry and platform allowlists, image load name checks, no signature verification documented)|Yes (cosign + enforce / warn modes)|self
Podman native libpod API|No (not documented, certified for Docker Engine 29 only)|Yes (default-deny /libpod coverage)|self
Tecnativa env compat|No|Yes|self
Config simplicity|Per-scope JSON files plus one YAML file|Full YAML config|tie
`,
  highlightsTable: `
shield|Different Models|YorvoGate gives each caller a scope (a Compose project, by token header, dedicated socket or client certificate) on a scoped listener, and keeps trusted listeners for endpoint groups. Sockguard uses ordered rules and per-client profiles. Which fits depends on whether you think in tenants or in rules.
key|Signed Policy Bundles|Sockguard verifies policy files with cosign keyed or keyless signatures and Rekor inclusion. YorvoGate signs its releases, and its documentation describes no signed policy files.
fingerprint|Container Image Trust|Sockguard can enforce image signatures on container and service creates. YorvoGate limits pull registries and platforms and checks names in loaded image archives, and documents no signature verification.
layers|Rollout Modes|Sockguard's per-profile rollout modes (enforce / warn / audit) let you shadow-test strict rules before they block anything. YorvoGate's documentation describes no such mode.
activity|Remote Upstream and Podman|Sockguard can reach a remote TLS daemon with failover and covers the libpod API. YorvoGate takes a unix-socket upstream and documents certification for Docker Engine 29 only.
users|Scope Isolation|YorvoGate documents per-scope request, connection and image-load bounds, and answers another scope's objects as Docker answers objects that don't exist. Sockguard's per-profile limits and owner labels cover similar ground, and we haven't compared the two under load.
`,
  highlightIconMap: {
    shield: "shield-check",
    key: "key",
    fingerprint: "fingerprint",
    layers: "stack",
    activity: "heartbeat",
    users: "users-three",
  },
  metadataTitle: "YorvoGate alternative: Sockguard vs YorvoGate",
  metadataDescription:
    "Sockguard as a YorvoGate alternative. Both inspect request bodies and keep clients apart; this page lists what each documents, from YorvoGate v0.4.0, with no parity claim.",
  metadataKeywords: [
    "yorvogate vs sockguard",
    "yorvogate alternative",
    "docker api policy gate comparison",
    "docker socket proxy body inspection",
    "docker socket proxy per-client scopes",
    "docker socket proxy signed policies",
  ],
  openGraphDescription:
    "YorvoGate and Sockguard both read request bodies and keep clients apart. See what each documents, sourced from YorvoGate v0.4.0.",
  twitterDescription: "Compare YorvoGate and Sockguard for Docker API policy enforcement.",
  competitorName: "YorvoGate",
  competitorTool: "yorvogate",
  heroTitle: "Sockguard: a YorvoGate alternative",
  heroDescription: (
    <p>
      Sockguard is a YorvoGate alternative for teams that want body-inspecting Docker API policy.
      YorvoGate (Apache-2.0, first released November 2026) also reads request bodies and scopes each
      client to its own Compose project, so the two overlap more than most pages here. This page
      lists what each project documents, read from YorvoGate v0.4.0 on 2026-11-26. Where Sockguard
      documents more, such as <strong>signed policy bundles, image trust, rollout modes</strong>, a
      remote TLS upstream and Podman libpod coverage, it says so. We haven&apos;t run YorvoGate
      against Sockguard&apos;s conformance suite, and a missing row in its documentation isn&apos;t
      proof the feature is absent.
    </p>
  ),
  migrationTitle: "Coming from YorvoGate?",
  migrationDescription:
    "There's no automatic translation. A YorvoGate scope (token hash, owner label, name prefixes) maps to a Sockguard client profile with an owner label, and its trusted-listener endpoint groups map to rule blocks. Sockguard's policy model is rule lists, so expect to rewrite the scope files by hand and to start from a bundled preset. YorvoGate documents Docker Engine 29 as its only certified major, so check your daemon version on either side.",
  jsonLdName: "YorvoGate alternative: Sockguard vs YorvoGate",
  jsonLdDescription: "Sockguard as a YorvoGate alternative.",
} satisfies ComparisonRouteRawConfig;
