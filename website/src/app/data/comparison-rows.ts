export interface ComparisonRow {
  feature: string;
  tecnativa: string;
  linuxserver: string;
  wollomatic: string;
  elevenNotes: string;
  cetusguard: string;
  sockguard: string;
  planned?: boolean;
}

export const comparisonRows: ComparisonRow[] = [
  {
    feature: "Method + path filtering",
    tecnativa: "Yes",
    linuxserver: "Yes",
    wollomatic: "Yes (regex)",
    elevenNotes: "Read-only (fixed)",
    cetusguard: "Yes (regex)",
    sockguard: "Yes",
  },
  {
    feature: "Granular POST ops",
    tecnativa: "Partial (ALLOW_* vars)",
    linuxserver: "Partial (ALLOW_* vars)",
    wollomatic: "Via regex",
    elevenNotes: "No (read-only)",
    cetusguard: "Via regex",
    sockguard: "Yes",
  },
  {
    feature: "Request body inspection",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "Partial (bind-mount restrictions)",
    elevenNotes: "No",
    cetusguard: "No",
    sockguard:
      "Yes (container, exec, image, build, volume, network, secret, config, service, swarm, node, plugin)",
  },
  {
    feature: "Per-client policies",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "Partial (IP/hostname + labels)",
    elevenNotes: "No",
    cetusguard: "No",
    sockguard: "CIDR + labels + cert selectors incl. SPKI + unix peer",
  },
  {
    feature: "Resource owner labels",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "No",
    elevenNotes: "No",
    cetusguard: "No",
    sockguard: "Yes (workload + control plane)",
  },
  {
    feature: "Remote TCP mTLS (listener)",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "No",
    elevenNotes: "No",
    cetusguard: "Yes",
    sockguard: "Yes (TLS 1.3)",
  },
  {
    feature: "Remote daemon upstream (TLS)",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "No",
    elevenNotes: "No",
    cetusguard: "Yes",
    sockguard: "Yes (active/passive failover)",
  },
  {
    feature: "Read-side visibility / redaction",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "No",
    elevenNotes:
      "Partial (targets 7 risky GETs; the image-export pattern misses both real shapes and has misfired on image inspect, 11notes #12)",
    cetusguard: "No",
    sockguard: "Yes (visibility + protected JSON redaction)",
  },
  {
    feature: "Structured access logs",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "Yes (JSON option)",
    elevenNotes: "No",
    cetusguard: "No",
    sockguard: "Yes (request + trace correlation)",
  },
  {
    feature: "Dedicated audit log schema",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "No",
    elevenNotes: "No",
    cetusguard: "No",
    sockguard: "Yes (opt-in, JSON schema + reason codes)",
  },
  {
    feature: "Prometheus metrics",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "No",
    elevenNotes: "No",
    cetusguard: "No",
    sockguard: "Yes (opt-in, socket-proxy metrics)",
  },
  {
    feature: "Active upstream watchdog",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "Yes",
    elevenNotes: "No",
    cetusguard: "No",
    sockguard: "Yes (opt-in watchdog; /health answers by default)",
  },
  {
    feature: "Trace/log correlation",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "No",
    elevenNotes: "No",
    cetusguard: "No",
    sockguard: "Yes (W3C traceparent)",
  },
  {
    feature: "YAML config",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "No",
    elevenNotes: "No",
    cetusguard: "No",
    sockguard: "Yes",
  },
  {
    feature: "Rate limits / concurrency caps",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "No",
    elevenNotes: "No",
    cetusguard: "No",
    sockguard: "Yes (per-profile token-bucket + global priority gate)",
  },
  {
    feature: "Rollout modes (enforce / warn / audit)",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "No",
    elevenNotes: "No",
    cetusguard: "No",
    sockguard: "Yes (per-profile shadow + would_deny audit)",
  },
  {
    feature: "Signed policy bundles",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "No",
    elevenNotes: "No",
    cetusguard: "No",
    sockguard: "Yes (cosign keyed + keyless, Rekor inclusion)",
  },
  {
    feature: "Container image trust",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "No",
    elevenNotes: "No",
    cetusguard: "No",
    sockguard: "Yes (cosign keyed + keyless, enforce / warn)",
  },
  {
    feature: "Podman native libpod API",
    tecnativa: "No",
    linuxserver: "Yes",
    wollomatic: "Via manual regex",
    elevenNotes: "No",
    cetusguard: "Yes",
    sockguard: "Yes (default-deny /libpod coverage incl. pod lifecycle)",
  },
  {
    feature: "Multiple main listeners",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "No",
    elevenNotes: "Yes (Unix + TCP)",
    cetusguard: "Yes",
    sockguard: "Yes (Unix and/or TCP, listener-scoped TLS + profiles)",
  },
  {
    feature: "Hot-reload + admin API",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "No",
    elevenNotes: "No",
    cetusguard: "No",
    sockguard: "Yes (opt-in, fsnotify/SIGHUP, validate endpoint, policy version)",
  },
];

// comparison-rows.ts is the single source of truth for every competitor claim
// the site makes. The /compare matrix and the landing-page teaser both show
// the same claims as a three-state icon instead of prose, so they derive their
// cells from those rows rather than restating them. They used to hardcode
// their own copies, which is how /compare came to say "partial" for wollomatic
// and CetusGuard path filtering while the row, the per-tool page it links to,
// and the README all said "Yes (regex)".

export type ComparisonCell = "yes" | "partial" | "no";

export type ComparisonTool =
  | "sockguard"
  | "tecnativa"
  | "linuxserver"
  | "wollomatic"
  | "elevenNotes"
  | "cetusguard";

// A row's cell is free text so it can carry the qualifier that makes the claim
// honest ("Yes (regex)", "Partial (bind-mount restrictions)", "Via manual
// regex"). Condensing it to an icon keeps only the verdict: a cell that opens
// with "Yes" is a yes, one that opens with "No" is a no, and everything else
// is a partial. The qualifier survives on the per-tool page and in the row
// itself, which is where a reader who wants it is going anyway.
export function toComparisonCell(value: string): ComparisonCell {
  if (/^yes\b/i.test(value)) {
    return "yes";
  }
  if (/^no\b/i.test(value)) {
    return "no";
  }
  return "partial";
}

export function comparisonCell(feature: string, tool: ComparisonTool): ComparisonCell {
  const row = comparisonRows.find((candidate) => candidate.feature === feature);
  if (!row) {
    // Unreachable while the feature names below match comparison-rows.ts;
    // page-data.test.mjs asserts every name resolves, so a renamed row fails
    // the test rather than quietly rendering an X on the live page.
    return "no";
  }
  return toComparisonCell(row[tool]);
}

// The /compare matrix axis. `row` names the comparison-rows.ts feature the
// column is derived from; `null` marks the two project-health columns, which
// are not policy claims and have no row.
export const MATRIX_FEATURES = [
  { key: "pathFilter", label: "Path filter", row: "Method + path filtering" },
  { key: "bodyInspect", label: "Body inspect", row: "Request body inspection" },
  { key: "perClient", label: "Per-client", row: "Per-client policies" },
  { key: "remoteMtls", label: "Remote mTLS", row: "Remote TCP mTLS (listener)" },
  { key: "signedBundles", label: "Signed bundles", row: "Signed policy bundles" },
  { key: "imageTrust", label: "Image trust", row: "Container image trust" },
  { key: "metrics", label: "Metrics", row: "Prometheus metrics" },
  { key: "podmanNative", label: "Podman native", row: "Podman native libpod API" },
  { key: "multipleListeners", label: "Multiple listeners", row: "Multiple main listeners" },
  { key: "maintained", label: "Maintained", row: null },
  { key: "openSource", label: "Open source", row: null },
] as const;

// Every tool in the matrix is currently maintained and open source, so these
// two columns are uniform. They stay explicit per tool rather than collapsing
// to a constant, because the day one of them stops being either is exactly
// when the column earns its place.
export const PROJECT_HEALTH: Record<
  ComparisonTool,
  Record<"maintained" | "openSource", ComparisonCell>
> = {
  sockguard: { maintained: "yes", openSource: "yes" },
  tecnativa: { maintained: "yes", openSource: "yes" },
  linuxserver: { maintained: "yes", openSource: "yes" },
  wollomatic: { maintained: "yes", openSource: "yes" },
  elevenNotes: { maintained: "yes", openSource: "yes" },
  cetusguard: { maintained: "yes", openSource: "yes" },
};

// The landing-page teaser: six rows, three rivals. `label` is the shorter
// wording the teaser uses; `row` is the comparison-rows.ts feature it means.
export const TEASER_FEATURES = [
  { label: "Method + path filtering", row: "Method + path filtering" },
  { label: "Request body inspection", row: "Request body inspection" },
  { label: "Per-client policies", row: "Per-client policies" },
  { label: "Remote TCP mTLS", row: "Remote TCP mTLS (listener)" },
  { label: "Signed policy bundles", row: "Signed policy bundles" },
  { label: "Prometheus metrics", row: "Prometheus metrics" },
] as const;
