interface ComparisonRow {
  feature: string;
  tecnativa: string;
  linuxserver: string;
  wollomatic: string;
  sockguard: string;
  planned?: boolean;
}

export const comparisonRows: ComparisonRow[] = [
  {
    feature: "Method + path filtering",
    tecnativa: "Yes",
    linuxserver: "Yes",
    wollomatic: "Yes (regex)",
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
    wollomatic: "Partial (bind-mount restrictions)",
    sockguard:
      "Yes (container, image, build, volume, network, secret, config, service, swarm, node, plugin)",
  },
  {
    feature: "Per-client policies",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "IP/hostname + labels",
    sockguard: "CIDR + labels + cert selectors incl. SPKI + unix peer",
  },
  {
    feature: "Resource owner labels",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "No",
    sockguard: "Yes (workload + control plane)",
  },
  {
    feature: "Remote TCP mTLS",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "No",
    sockguard: "Yes (TLS 1.3)",
  },
  {
    feature: "Read-side visibility / redaction",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "No",
    sockguard: "Yes (visibility + protected JSON redaction)",
  },
  {
    feature: "Structured access logs",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "Yes (JSON option)",
    sockguard: "Yes (request + trace correlation)",
  },
  {
    feature: "Dedicated audit log schema",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "No",
    sockguard: "Yes (JSON schema + reason codes)",
  },
  {
    feature: "Prometheus metrics",
    tecnativa: "HAProxy stats",
    linuxserver: "nginx status",
    wollomatic: "No",
    sockguard: "Yes (socket-proxy metrics)",
  },
  {
    feature: "Active upstream watchdog",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "Yes",
    sockguard: "Yes (+ /health + metrics)",
  },
  {
    feature: "Trace/log correlation",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "No",
    sockguard: "Yes (W3C traceparent)",
  },
  {
    feature: "YAML config",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "No",
    sockguard: "Yes",
  },
  {
    feature: "Rate limits / concurrency caps",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "No",
    sockguard: "Yes (per-profile token-bucket + global priority gate)",
  },
  {
    feature: "Rollout modes (enforce / warn / audit)",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "No",
    sockguard: "Yes (per-profile shadow + would_deny audit)",
  },
  {
    feature: "Signed policy bundles",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "No",
    sockguard: "Yes (cosign keyed + keyless, Rekor inclusion)",
  },
  {
    feature: "Hot-reload + admin API",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "No",
    sockguard: "Yes (fsnotify/SIGHUP, validate endpoint, policy version)",
  },
];
