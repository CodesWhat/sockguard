import {
  ArrowRight,
  FileText,
  Shield,
  ShieldCheck,
  SlidersHorizontal,
  type LucideIcon,
  Zap,
} from "lucide-react";

export type FeatureCategory = "security" | "control" | "operations";

export interface Feature {
  icon: LucideIcon;
  title: string;
  color: string;
  bg: string;
  description: string;
  category: FeatureCategory;
}

export const features: Feature[] = [
  {
    icon: ShieldCheck,
    title: "Default-Deny Posture",
    color: "text-rose-500 dark:text-rose-400",
    bg: "bg-rose-100 dark:bg-rose-900/50",
    description: "Everything blocked unless explicitly allowed. No match means deny.",
    category: "security",
  },
  {
    icon: SlidersHorizontal,
    title: "Granular Control",
    color: "text-blue-500 dark:text-blue-400",
    bg: "bg-blue-100 dark:bg-blue-900/50",
    description:
      "Allow start/stop while blocking create/exec. Per-operation POST controls with glob matching.",
    category: "control",
  },
  {
    icon: Zap,
    title: "Structured Logging",
    color: "text-emerald-500 dark:text-emerald-400",
    bg: "bg-emerald-100 dark:bg-emerald-900/50",
    description:
      "JSON access logs with method, path, decision, matched rule index, latency, and client info.",
    category: "operations",
  },
  {
    icon: FileText,
    title: "YAML Configuration",
    color: "text-blue-500 dark:text-blue-400",
    bg: "bg-blue-100 dark:bg-blue-900/50",
    description:
      "Declarative rules in YAML. Glob patterns for paths, first-match-wins evaluation, 10 bundled presets.",
    category: "control",
  },
  {
    icon: ArrowRight,
    title: "Tecnativa Compatible",
    color: "text-emerald-500 dark:text-emerald-400",
    bg: "bg-emerald-100 dark:bg-emerald-900/50",
    description:
      "Drop-in replacement using the same env vars. CONTAINERS=1, POST=0, ALLOW_START=1 all work.",
    category: "operations",
  },
  {
    icon: Shield,
    title: "Minimal Attack Surface",
    color: "text-rose-500 dark:text-rose-400",
    bg: "bg-rose-100 dark:bg-rose-900/50",
    description:
      "Wolfi-based image, ~12MB, near-zero CVEs. Cosign-signed with SBOM and build provenance.",
    category: "security",
  },
];
