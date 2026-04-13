export interface ComparisonRow {
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
    wollomatic: "Yes",
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
    wollomatic: "No",
    sockguard: "Yes (/containers/create)",
  },
  {
    feature: "Per-client policies",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "CIDR + labels",
    sockguard: "CIDR + labels",
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
    sockguard: "Planned",
    planned: true,
  },
  {
    feature: "Structured audit log",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "No",
    sockguard: "Yes",
  },
  {
    feature: "YAML config",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "No",
    sockguard: "Yes",
  },
];
