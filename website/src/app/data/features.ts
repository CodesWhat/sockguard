import {
  ArrowRight,
  EyeOff,
  FileText,
  LockKeyhole,
  type LucideIcon,
  Network,
  ScanSearch,
  Shield,
  ShieldCheck,
  SlidersHorizontal,
  Tag,
  UsersRound,
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
    description:
      "Everything blocked unless explicitly allowed. Request paths are percent-decoded and canonicalized before matching, so `%2e%2e` and encoded-separator tricks cannot slip past an allowlist.",
    category: "security",
  },
  {
    icon: ScanSearch,
    title: "Request Body Inspection",
    color: "text-rose-500 dark:text-rose-400",
    bg: "bg-rose-100 dark:bg-rose-900/50",
    description:
      "Container, volume, secret, config, service, swarm, image-pull, build, and plugin writes are parsed to block host-bound workloads, non-allowlisted mounts, devices, commands, and remotes, unsafe swarm rotations, and remote build contexts. Multipart plugin uploads are inspected too, and oversized bounded bodies are rejected with 413 before the inspector runs.",
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
      "Stamp label-capable creates, node/swarm claim updates, and build images with an owner label. Labeled list, prune, and event reads are auto-filtered, and cross-owner access is denied across workload and control-plane resources.",
    category: "control",
  },
  {
    icon: Network,
    title: "Client ACL Primitives",
    color: "text-blue-500 dark:text-blue-400",
    bg: "bg-blue-100 dark:bg-blue-900/50",
    description:
      "Gate callers by source CIDR, bridge-network container labels, mTLS certificate selectors (CN, DNS/IP/URI SAN, SHA-256 SPKI pin), and unix peer credentials before the global policy runs.",
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
    title: "Structured Access Logging",
    color: "text-emerald-500 dark:text-emerald-400",
    bg: "bg-emerald-100 dark:bg-emerald-900/50",
    description:
      "JSON access logs with method, path, decision, matched rule index, latency, canonical request_id, and client info.",
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
      "Drop-in replacement for the current Tecnativa env surface, including section vars, ALLOW_RESTARTS, SOCKET_PATH, and LOG_LEVEL.",
    category: "operations",
  },
  {
    icon: Shield,
    title: "Minimal Attack Surface",
    color: "text-rose-500 dark:text-rose-400",
    bg: "bg-rose-100 dark:bg-rose-900/50",
    description: "Wolfi-based image. Cosign-signed with SBOM and build provenance.",
    category: "security",
  },
  {
    icon: EyeOff,
    title: "Visibility-Controlled Reads",
    color: "text-rose-500 dark:text-rose-400",
    bg: "bg-rose-100 dark:bg-rose-900/50",
    description:
      "Label selectors hide labeled list, inspect, and log reads for non-matching resources, env/mount/network/config/plugin/swarm-sensitive metadata is redacted by default, and raw archive/export reads stay behind explicit opt-in.",
    category: "security",
  },
  {
    icon: UsersRound,
    title: "Named Client Profiles",
    color: "text-blue-500 dark:text-blue-400",
    bg: "bg-blue-100 dark:bg-blue-900/50",
    description:
      "Route callers to named profiles with their own rules and request-body policy by source CIDR or mTLS client certificate, with a configurable default fallback.",
    category: "control",
  },
];
