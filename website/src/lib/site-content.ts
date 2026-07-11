export type Milestone = {
  version: string;
  title: string;
  emoji: string;
  status: "released" | "next" | "planned";
  items: string[];
};

export const roadmap: Milestone[] = [
  {
    version: "v1.0.0",
    title: "Foundation",
    emoji: "✅",
    status: "released",
    items: [
      "Default-deny proxy: method + path filtering with percent-decoded path canonicalization",
      "Request body inspection (container, exec, image, build, volume, network, secret, config, service, swarm, node, plugin)",
      "Mutual TLS 1.3 enforced on all non-loopback TCP listeners",
      "Signed policy bundles (cosign keyed + keyless, Rekor inclusion proof)",
      "Container image trust (cosign verify before /containers/create, enforce / warn modes)",
      "Owner label isolation for workload and control-plane resources",
      "Client ACL primitives: CIDR, mTLS cert selectors, unix peer credentials",
      "Named client profiles with per-profile rollout modes (enforce / warn / audit)",
      "12 bundled policy presets: drydock, Traefik, Portainer, Watchtower, CIS Docker Benchmark, GitHub Actions runner, GitLab Runner, and more",
    ],
  },
  {
    version: "v1.1.0",
    title: "Security Hardening",
    emoji: "🔒",
    status: "released",
    items: [
      "21 HIGH + MEDIUM security findings fixed across a full multi-axis audit",
      "Image-trust wired end-to-end — cosign signatures verified against resolved manifest digest, TOCTOU sealed",
      "Plugin install, service create/update, and docker load bypass vectors closed",
      "Ownership isolation: bounded LRU caches, negative-cache closed, image /get gated",
      "Response redaction gaps closed (Mounts source, PreviousSpec, MaskedPaths/ReadonlyPaths)",
      "Constant-time SPKI pin comparison; gzip-bomb guards on build and plugin paths",
      "QA harness: proxy-vs-daemon differential, mTLS edge-case suite, fuzz targets, goroutine-leak soak",
    ],
  },
  {
    version: "v1.2.0",
    title: "Resilience & Observability",
    emoji: "📊",
    status: "released",
    items: [
      "Opt-in upstream readiness probe (GET /containers/json health check — returns 503 on a wedged daemon)",
      "upstream.request_timeout — 504 Gateway Timeout on hung proxied finite requests",
      "Upstream response-header timeout hardened across all side-channel transports",
      "drydock preset: allowlisted runc runtime to fix update recreate rollbacks",
      "Go toolchain bumped to 1.26.4 — clears two reachable stdlib advisories (GO-2026-5037, GO-2026-5039)",
    ],
  },
  {
    version: "v1.3.0",
    title: "Posture Hardening",
    emoji: "🛡️",
    status: "released",
    items: [
      "Swarm service create/update enforces container-create identity/privilege rails (non-root, no-new-privileges, readonly rootfs, drop ALL)",
      "Zero-padded UID bypass sealed — '00', '000', '0:0' all parsed numerically as root",
      "Wide-open dedicated admin listener rejected at config validation, not just warned",
      "Admin endpoint paths normalized before matching — trailing-slash and dot-segment variants closed",
      "signature_path hot-reload wedge fixed — verification reads from candidate config",
      "Non-upgrade hijack responses strip hop-by-hop headers",
      "Multi-arch images cross-compile natively (no QEMU emulation in CI)",
    ],
  },
  {
    version: "v1.4.0",
    title: "Remote Upstreams & Fleet Presets",
    emoji: "🌐",
    status: "released",
    items: [
      "Remote Docker daemon over TCP with mutual TLS and active/passive failover",
      "Ordered endpoint failover — connect failure instantly promotes next endpoint without retry",
      "Portwing presets (portwing.yaml, portwing-with-exec.yaml) and drydock-with-selfupdate.yaml",
      "Drydock preset conformance audit — runc runtime, multi-network connect, self-update finalize exec all fixed",
      "Swarm service seccomp/AppArmor confinement rails (deny_unconfined_seccomp, deny_unconfined_apparmor)",
      "Rate-limit token bucket: allocation-free hot path, 0 allocs/0 B per op at ~36 ns",
      "Enforced CI coverage floor (96%) with Qlty Cloud reporting",
    ],
  },
  {
    version: "v1.5.0",
    title: "Safer Defaults & Namespace Hardening",
    emoji: "🔧",
    status: "next",
    items: [
      "upstream.request_timeout now defaults to 60s (was unlimited); 'off' restores unlimited",
      "ownership.allow_cross_owner_namespace_sharing defaults to false — cross-owner container:<id> namespace joins denied by default when ownership.owner is set",
      "Namespace-sharing gate: restrict_namespace_sharing + allowed_namespace_sharing_containers gate container:<id> joins across NetworkMode/PidMode/IpcMode/UsernsMode; deny_namespace_path_mode blocks raw ns:<path> on NetworkMode only",
      "allow_host_cgroupns (default false) extends the host-mode denials to HostConfig.CgroupnsMode — the one host namespace the allow_host_* family didn't previously gate",
      "require_cpu_limit_hard — opt-in hard CPU-time cap (NanoCpus/CpuQuota), independent of require_cpu_limit",
      "Exec Env allow/denylisting — request_body.exec.allowed_env_vars/denied_env_vars, denylist wins",
      "New presets: portwing-with-compose.yaml, drydock-with-compose.yaml, plus a tri-tool compose example",
      "Helm chart: pod-level podSecurityContext",
      "Config Viper-default registration generated by reflection off Defaults()",
    ],
  },
];
