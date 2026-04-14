import {
  ArrowRight,
  FileText,
  LockKeyhole,
  type LucideIcon,
  Network,
  ScanSearch,
  Shield,
  ShieldCheck,
  SlidersHorizontal,
  Tag,
  Zap,
} from "lucide-react";

export type FeatureCategory = "security" | "control" | "operations";

interface Feature {
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
    icon: ScanSearch,
    title: "Request Body Inspection",
    color: "text-rose-500 dark:text-rose-400",
    bg: "bg-rose-100 dark:bg-rose-900/50",
    description:
      "POST /containers/create bodies are parsed to block privileged containers, host networking, and non-allowlisted bind mounts before Docker ever sees the request.",
    category: "security",
  },
  {
    icon: LockKeyhole,
    title: "mTLS for Remote TCP",
    color: "text-rose-500 dark:text-rose-400",
    bg: "bg-rose-100 dark:bg-rose-900/50",
    description:
      "Non-loopback TCP listeners require mutual TLS 1.3 by default. Plaintext remote TCP is explicit legacy opt-in only.",
    category: "security",
  },
  {
    icon: Tag,
    title: "Owner Label Isolation",
    color: "text-blue-500 dark:text-blue-400",
    bg: "bg-blue-100 dark:bg-blue-900/50",
    description:
      "Stamp containers, networks, volumes, and build images with an owner label. List and prune calls are auto-filtered, and cross-owner access is denied.",
    category: "control",
  },
  {
    icon: Network,
    title: "Client ACL Primitives",
    color: "text-blue-500 dark:text-blue-400",
    bg: "bg-blue-100 dark:bg-blue-900/50",
    description:
      "Gate callers by source CIDR and enforce per-client allowlists resolved from the calling container's labels over the bridge network.",
    category: "control",
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
    description: "Wolfi-based image, ~12MB. Cosign-signed with SBOM and build provenance.",
    category: "security",
  },
];
