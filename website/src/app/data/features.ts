import {
  Activity,
  ArrowRight,
  BadgeCheck,
  EyeOff,
  FileText,
  Gauge,
  LockKeyhole,
  type LucideIcon,
  Network,
  RefreshCw,
  ScanSearch,
  Shield,
  ShieldCheck,
  SlidersHorizontal,
  Tag,
  Timer,
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
      "Container, image, build, volume, network, secret, config, service, swarm, node, and plugin writes are parsed to block privileged or host-namespace workloads, non-allowlisted mounts/devices, device requests, device cgroup rules, commands, remotes, unsafe network/swarm/node controls, archive writes, and tar imports. Multipart plugin uploads are inspected too, and oversized bounded bodies are rejected with 413 before the inspector runs.",
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
      "JSON access logs with method, raw and normalized paths, decision, matched rule index, latency, canonical request_id, preserved client request IDs, and W3C trace correlation fields.",
    category: "operations",
  },
  {
    icon: Activity,
    title: "Operator Observability",
    color: "text-emerald-500 dark:text-emerald-400",
    bg: "bg-emerald-100 dark:bg-emerald-900/50",
    description:
      "Opt-in Prometheus metrics expose request totals, deny counts, latency buckets, active requests, watchdog state, plus build_info and start_time gauges for version panels and uptime alerts. The active Docker socket watchdog feeds /health and logs state transitions, while trace/log correlation works without an OTLP exporter.",
    category: "operations",
  },
  {
    icon: FileText,
    title: "YAML Configuration",
    color: "text-blue-500 dark:text-blue-400",
    bg: "bg-blue-100 dark:bg-blue-900/50",
    description:
      "Declarative rules in YAML. Glob patterns for paths, first-match-wins evaluation, and 9 bundled workload presets plus the default config.",
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
    icon: BadgeCheck,
    title: "Signed Policy Bundles",
    color: "text-rose-500 dark:text-rose-400",
    bg: "bg-rose-100 dark:bg-rose-900/50",
    description:
      "Treat the on-disk YAML config as untrusted until a cosign / sigstore bundle confirms it. Supports keyed (PEM ECDSA/RSA/ed25519) and keyless (Fulcio + Rekor) verification. Bundle is checked at startup and on every hot reload — a bad signature rejects the reload and leaves the running policy untouched.",
    category: "security",
  },
  {
    icon: EyeOff,
    title: "Visibility-Controlled Reads",
    color: "text-rose-500 dark:text-rose-400",
    bg: "bg-rose-100 dark:bg-rose-900/50",
    description:
      "Label selectors hide labeled list, inspect, and selected service/task log reads for non-matching resources, env/mount/network/config/plugin/swarm-sensitive metadata is redacted by default, and raw archive/export reads stay behind explicit opt-in.",
    category: "security",
  },
  {
    icon: UsersRound,
    title: "Named Client Profiles",
    color: "text-blue-500 dark:text-blue-400",
    bg: "bg-blue-100 dark:bg-blue-900/50",
    description:
      "Route callers to named profiles with their own rules and request-body policy by source CIDR, mTLS client certificate selectors including SPKI pins, or unix peer credentials, with a configurable default fallback.",
    category: "control",
  },
  {
    icon: Timer,
    title: "Rate Limits & Concurrency Caps",
    color: "text-blue-500 dark:text-blue-400",
    bg: "bg-blue-100 dark:bg-blue-900/50",
    description:
      "Per-profile token-bucket rate limiting (`limits.rate`) and in-flight concurrency caps (`limits.concurrency`) return `429 Too Many Requests` with `Retry-After` when exhausted. A system-wide priority fairness gate (`clients.global_concurrency`) prevents low-priority callers from starving high-priority profiles. Anonymous callers bucket under `_anonymous` so they cannot bypass limits by skipping identification.",
    category: "control",
  },
  {
    icon: Gauge,
    title: "Per-Profile Rollout Modes",
    color: "text-blue-500 dark:text-blue-400",
    bg: "bg-blue-100 dark:bg-blue-900/50",
    description:
      "Stage policy changes without blocking traffic. Set a profile to `warn` or `audit` to serve requests while logging `decision=would_deny` audit records — then compare blocked vs. would-have-been-blocked in your dashboards before flipping to `enforce`. Pre-auth gates (CIDR allowlist, identity failures) always stay in enforce regardless of profile mode.",
    category: "control",
  },
  {
    icon: RefreshCw,
    title: "Hot-Reload + Admin API",
    color: "text-emerald-500 dark:text-emerald-400",
    bg: "bg-emerald-100 dark:bg-emerald-900/50",
    description:
      "fsnotify file watch and SIGHUP reload with immutable-field gating — listener, upstream socket, and trust-material fields require a restart. `POST /admin/validate` dry-runs a candidate config without touching the running policy. `GET /admin/policy/version` returns the generation counter, config SHA-256, and verified bundle signer. Optionally binds the admin API to a dedicated listener so admin traffic never traverses the Docker-API filter chain.",
    category: "operations",
  },
];
