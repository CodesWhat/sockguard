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
    sockguard: "Yes (create, exec, pull, build)",
  },
  {
    feature: "Per-client policies",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "IP/hostname + labels",
    sockguard: "CIDR + labels + cert profiles",
  },
  {
    feature: "Resource owner labels",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "No",
    sockguard: "Yes",
  },
  {
    feature: "Remote TCP mTLS",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "No",
    sockguard: "Yes (TLS 1.3)",
  },
  {
    feature: "Response filtering",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "No",
    sockguard: "Yes (visibility + redaction)",
  },
  {
    feature: "Structured access logs",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "Yes (JSON option)",
    sockguard: "Yes",
  },
  {
    feature: "Dedicated audit log schema",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "No",
    sockguard: "Roadmap",
  },
  {
    feature: "YAML config",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "No",
    sockguard: "Yes",
  },
];
