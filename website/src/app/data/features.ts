import {
  Activity,
  ArrowRight,
  BadgeCheck,
  EyeOff,
  FileText,
  Fingerprint,
  Gauge,
  LockKeyhole,
  type LucideIcon,
  Network,
  RefreshCw,
  ScanSearch,
  Server,
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
      "We parse every container, image, build, volume, network, secret, config, service, swarm, node, and plugin write to block privileged or host-namespace workloads, non-allowlisted mounts/devices, unsafe controls, archive writes, and tar imports. Native Podman builds add fail-closed primary/additional-context, host-mount, and resource-usage host-file handling on top of the shared classic-build policy. Bounded inspectors reject oversized bodies with 413 and enforce a 30-second read deadline through logging and metrics.",
    category: "security",
  },
  {
    icon: LockKeyhole,
    title: "mTLS for Remote TCP",
    color: "text-rose-500 dark:text-rose-400",
    bg: "bg-rose-100 dark:bg-rose-900/50",
    description:
      "We require mutual TLS 1.3 on non-loopback TCP listeners by default. Plaintext remote TCP is an explicit legacy opt-in only.",
    category: "security",
  },
  {
    icon: Tag,
    title: "Owner Label Isolation",
    color: "text-blue-500 dark:text-blue-400",
    bg: "bg-blue-100 dark:bg-blue-900/50",
    description:
      "Stamp label-capable creates, node/swarm claim updates, and build images with an owner label. Labeled list, prune, and event reads are auto-filtered, cross-owner access is denied, and method-aware path handling keeps resources named after API actions inside the boundary.",
    category: "control",
  },
  {
    icon: Network,
    title: "Client ACL Primitives",
    color: "text-blue-500 dark:text-blue-400",
    bg: "bg-blue-100 dark:bg-blue-900/50",
    description:
      "Gate callers by source CIDR, bridge-network container labels, mTLS certificate selectors (CN, DNS/IP/URI SAN, SHA-256 SPKI pin), and unix peer credentials before the global policy runs. The trusted principal and selected profile also isolate mediated BuildKit session state.",
    category: "control",
  },
  {
    icon: SlidersHorizontal,
    title: "Granular Control",
    color: "text-blue-500 dark:text-blue-400",
    bg: "bg-blue-100 dark:bg-blue-900/50",
    description:
      "You can allow start/stop while blocking create/exec. We give you per-operation POST controls with glob matching.",
    category: "control",
  },
  {
    icon: Zap,
    title: "Structured Access Logging",
    color: "text-amber-500 dark:text-amber-400",
    bg: "bg-amber-100 dark:bg-amber-900/50",
    description:
      "We emit JSON access logs with method, raw and normalized paths, decision, matched rule index, latency, canonical request_id, preserved client request IDs, and W3C trace correlation fields.",
    category: "operations",
  },
  {
    icon: Activity,
    title: "Operator Observability",
    color: "text-amber-500 dark:text-amber-400",
    bg: "bg-amber-100 dark:bg-amber-900/50",
    description:
      "Our opt-in Prometheus metrics expose request totals, deny counts, latency buckets, active requests, watchdog state, plus build_info and start_time gauges. Method and unknown-route labels are finite, so caller-controlled values cannot grow the registry without bound. Trace/log correlation works without an OTLP exporter.",
    category: "operations",
  },
  {
    icon: FileText,
    title: "YAML Configuration",
    color: "text-blue-500 dark:text-blue-400",
    bg: "bg-blue-100 dark:bg-blue-900/50",
    description:
      "We use declarative YAML rules with glob patterns, first-match-wins evaluation, and 17 bundled workload presets (drydock, drydock with self-update, drydock with compose, Traefik, Portainer, Watchtower, Homepage, Homarr, Diun, Autoheal, read-only, CIS Docker Benchmark, GitHub Actions self-hosted runner, GitLab Runner, Portwing, Portwing with exec, Portwing with compose) plus the default config.",
    category: "control",
  },
  {
    icon: ArrowRight,
    title: "Tecnativa Compatible",
    color: "text-amber-500 dark:text-amber-400",
    bg: "bg-amber-100 dark:bg-amber-900/50",
    description:
      "Migrating from Tecnativa? We match its full env surface in unsigned mode: section vars, ALLOW_RESTARTS, SOCKET_PATH, and LOG_LEVEL. Signed policies reject rule-generating compatibility variables so environment state cannot change verified rules.",
    category: "operations",
  },
  {
    icon: Shield,
    title: "Minimal Attack Surface",
    color: "text-rose-500 dark:text-rose-400",
    bg: "bg-rose-100 dark:bg-rose-900/50",
    description: "We ship a Wolfi-based image, cosign-signed with SBOM and build provenance.",
    category: "security",
  },
  {
    icon: BadgeCheck,
    title: "Signed Policy Bundles",
    color: "text-rose-500 dark:text-rose-400",
    bg: "bg-rose-100 dark:bg-rose-900/50",
    description:
      "Pin keyed or keyless sigstore trust in a separate bootstrap file selected with --policy-bundle-trust-config. Candidate and trust YAML stop at 16 MiB, bundles at 4 MiB, and cooperative cancellation stops signer fallback. Startup and every hot reload verify before applying policy.",
    category: "security",
  },
  {
    icon: Fingerprint,
    title: "Container Image Trust",
    color: "text-rose-500 dark:text-rose-400",
    bg: "bg-rose-100 dark:bg-rose-900/50",
    description:
      "Verify cosign signatures on a container's image before `POST /containers/create` reaches the daemon. Keyed and keyless trust is configurable per client profile, with redirect-safe registry response limits, direct-manifest signature references, no alternate payload URLs, bounded signature fan-out, and aggregate payload budgets. Legal media-type parameters remain compatible. `enforce` denies unsigned or wrong-signer images; `warn` logs the failure and forwards the request.",
    category: "security",
  },
  {
    icon: EyeOff,
    title: "Visibility-Controlled Reads",
    color: "text-rose-500 dark:text-rose-400",
    bg: "bg-rose-100 dark:bg-rose-900/50",
    description:
      "We use label selectors to hide labeled list, inspect, and selected service/task log reads. Keyword-named resources stay covered, and combined label plus name/image checks use one bounded inspect. Sensitive metadata is redacted by default, while raw archive/export reads require explicit opt-in.",
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
      "We return `429 Too Many Requests` with `Retry-After` when per-profile token-bucket rate limits (`limits.rate`) or in-flight concurrency caps (`limits.concurrency`) are exhausted. A system-wide priority fairness gate (`clients.global_concurrency`) prevents low-priority callers from starving high-priority profiles. Anonymous callers bucket under `_anonymous` so they can't bypass limits by skipping identification.",
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
    color: "text-amber-500 dark:text-amber-400",
    bg: "bg-amber-100 dark:bg-amber-900/50",
    description:
      "We watch for config changes with fsnotify and support SIGHUP reload with immutable-field gating. Signed trust stays pinned in the separate bootstrap file; only the candidate's signature path rotates on reload. `POST /admin/validate` dry-runs a candidate, and `GET /admin/policy/version` returns its generation, SHA-256, and verified signer.",
    category: "operations",
  },
  {
    icon: Server,
    title: "Remote Upstreams & Failover",
    color: "text-amber-500 dark:text-amber-400",
    bg: "bg-amber-100 dark:bg-amber-900/50",
    description:
      "Dial a remote Docker daemon over TCP with mutual TLS instead of the local socket. Configure an ordered set of redundant endpoints for the same daemon or swarm node with active health checks and automatic failover.",
    category: "operations",
  },
];
