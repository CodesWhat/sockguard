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
    sockguard: "Planned",
    planned: true,
  },
  {
    feature: "Per-client policies",
    tecnativa: "No",
    linuxserver: "No",
    wollomatic: "IP only",
    sockguard: "Planned",
    planned: true,
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
