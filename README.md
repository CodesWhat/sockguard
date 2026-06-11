<div align="center">

<img src="sockguard-logo.png" alt="sockguard" width="180">

<h1>sockguard</h1>

**Control what gets through. A default-deny Docker socket proxy built in Go.**

</div>

<p align="center">
  <a href="https://github.com/CodesWhat/sockguard/releases"><img src="https://img.shields.io/github/v/release/CodesWhat/sockguard?include_prereleases&label=release" alt="Release"></a>
  <a href="https://github.com/CodesWhat/sockguard/releases"><img src="https://img.shields.io/github/downloads/CodesWhat/sockguard/total?label=downloads" alt="Release downloads"></a>
  <a href="https://github.com/CodesWhat/sockguard/pkgs/container/sockguard"><img src="https://img.shields.io/badge/GHCR-image-2ea44f?logo=github&logoColor=white" alt="GHCR"></a>
  <a href="https://hub.docker.com/r/codeswhat/sockguard"><img src="https://img.shields.io/docker/pulls/codeswhat/sockguard?logo=docker&logoColor=white&label=Docker+Hub" alt="Docker Hub pulls"></a>
  <a href="https://quay.io/repository/codeswhat/sockguard"><img src="https://img.shields.io/badge/Quay.io-image-ee0000?logo=redhat&logoColor=white" alt="Quay.io"></a>
  <br>
  <a href="https://github.com/orgs/CodesWhat/packages/container/package/sockguard"><img src="https://img.shields.io/badge/platforms-amd64%20%7C%20arm64-informational?logo=linux&logoColor=white" alt="Multi-arch"></a>
  <a href="https://github.com/orgs/CodesWhat/packages/container/package/sockguard"><img src="https://img.shields.io/docker/image-size/codeswhat/sockguard/latest?logo=docker&logoColor=white&label=image%20size" alt="Image size"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-C9A227" alt="License Apache-2.0"></a>
</p>

<p align="center">
  <a href="https://github.com/CodesWhat/sockguard/stargazers"><img src="https://img.shields.io/github/stars/CodesWhat/sockguard?style=flat" alt="Stars"></a>
  <a href="https://github.com/CodesWhat/sockguard/forks"><img src="https://img.shields.io/github/forks/CodesWhat/sockguard?style=flat" alt="Forks"></a>
  <a href="https://github.com/CodesWhat/sockguard/issues"><img src="https://img.shields.io/github/issues/CodesWhat/sockguard?style=flat" alt="Issues"></a>
  <a href="https://github.com/CodesWhat/sockguard/commits/main"><img src="https://img.shields.io/github/last-commit/CodesWhat/sockguard?style=flat" alt="Last commit"></a>
  <a href="https://github.com/CodesWhat/sockguard/commits/main"><img src="https://img.shields.io/github/commit-activity/m/CodesWhat/sockguard?style=flat" alt="Commit activity"></a>
  <br>
  <a href="https://github.com/CodesWhat/sockguard/discussions"><img src="https://img.shields.io/github/discussions/CodesWhat/sockguard?style=flat" alt="Discussions"></a>
  <a href="https://github.com/CodesWhat/sockguard"><img src="https://img.shields.io/github/repo-size/CodesWhat/sockguard?style=flat" alt="Repo size"></a>
  <img src="https://komarev.com/ghpvc/?username=CodesWhat-sockguard&label=repo+views&style=flat" alt="Repo views">
</p>

<p align="center">
  <a href="https://github.com/CodesWhat/sockguard/actions/workflows/ci-verify.yml"><img src="https://github.com/CodesWhat/sockguard/actions/workflows/ci-verify.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="https://github.com/CodesWhat/sockguard/actions/workflows/quality-integration.yml"><img src="https://github.com/CodesWhat/sockguard/actions/workflows/quality-integration.yml/badge.svg?branch=main" alt="Integration"></a>
  <a href="https://github.com/CodesWhat/sockguard/actions/workflows/quality-fuzz-nightly.yml"><img src="https://github.com/CodesWhat/sockguard/actions/workflows/quality-fuzz-nightly.yml/badge.svg?branch=main" alt="Nightly fuzz"></a>
  <br>
  <a href="https://goreportcard.com/report/github.com/CodesWhat/sockguard/app"><img src="https://goreportcard.com/badge/github.com/CodesWhat/sockguard/app" alt="Go Report Card"></a>
  <a href="https://pkg.go.dev/github.com/CodesWhat/sockguard"><img src="https://pkg.go.dev/badge/github.com/CodesWhat/sockguard.svg" alt="Go Reference"></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/CodesWhat/sockguard"><img src="https://img.shields.io/ossf-scorecard/github.com/CodesWhat/sockguard?label=openssf+scorecard&style=flat" alt="OpenSSF Scorecard"></a>
  <a href="https://github.com/CodesWhat/sockguard/actions/workflows/security-grype-weekly.yml"><img src="https://github.com/CodesWhat/sockguard/actions/workflows/security-grype-weekly.yml/badge.svg?branch=main" alt="Weekly Grype"></a>
  <a href="https://github.com/CodesWhat/sockguard/actions/workflows/quality-mutation-monthly.yml"><img src="https://img.shields.io/badge/mutation%20score-96%25-brightgreen?logo=go&logoColor=white" alt="Mutation score"></a>
</p>

<hr>

<h2 align="center">📑 Contents</h2>

- [📖 Documentation](https://getsockguard.com/docs)
- [🌐 Website](https://getsockguard.com)
- [🚀 Quick Start](#quick-start)
- [🆕 Recent Updates](#recent-updates)
- [🤔 Why Sockguard](#why-sockguard)
- [✨ Features](#features)
- [🔌 Supported Profiles](#supported-profiles)
- [⚖️ Feature Comparison](#feature-comparison)
- [⚙️ Configuration](#configuration)
- [🔧 CLI](#cli)
- [🔄 Migration](#migration)
- [🗺️ Roadmap](#roadmap)
- [📖 Documentation](#documentation)
- [⭐ Star History](#star-history)
- [🛠️ Built With](#built-with)
- [🤝 Community & Support](#community--support)

<hr>

> [!NOTE]
> **v1.2.0 is released.** The YAML schema, CLI flags, env vars, admin endpoints, and Prometheus metric names are stable under the v1.x contract. See [CHANGELOG.md](CHANGELOG.md) for the latest release notes and the current `Unreleased` work.

<h2 align="center" id="quick-start">🚀 Quick Start</h2>

Drop sockguard in front of any Docker API consumer. The proxy filters requests, your app stays unchanged.

```yaml
# docker-compose.yml
services:
  sockguard:
    image: codeswhat/sockguard:latest
    restart: unless-stopped
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      - SOCKGUARD_LISTEN_ADDRESS=:2375
      - SOCKGUARD_LISTEN_INSECURE_ALLOW_PLAIN_TCP=true
      - SOCKGUARD_LISTEN_INSECURE_ALLOW_UNAUTHENTICATED_CLIENTS=true
      - SOCKGUARD_INSECURE_ALLOW_READ_EXFILTRATION=true
      - CONTAINERS=1
      - IMAGES=1
      - EVENTS=1

  # Your app talks to tcp://sockguard:2375 over the compose network
  # instead of mounting /var/run/docker.sock.
  drydock:
    image: codeswhat/drydock:latest
    depends_on:
      - sockguard
    environment:
      - DD_WATCHER_LOCAL_SOCKET=tcp://sockguard:2375
```

By default sockguard listens on loopback TCP `127.0.0.1:2375`, not on all interfaces. Non-loopback TCP now requires mutual TLS via `listen.tls` by default.

The compose example above opts into **legacy plaintext TCP** so migration from `tecnativa/docker-socket-proxy` and `linuxserver/socket-proxy` still works on a private Docker network. A non-loopback plaintext listener requires **two** deliberate acknowledgments — `SOCKGUARD_LISTEN_INSECURE_ALLOW_PLAIN_TCP=true` (unencrypted transport) and `SOCKGUARD_LISTEN_INSECURE_ALLOW_UNAUTHENTICATED_CLIENTS=true` (any host that can reach the port can impersonate a client) — so a single fat-fingered flag cannot expose it. It also opts into `SOCKGUARD_INSECURE_ALLOW_READ_EXFILTRATION=true` because broad `CONTAINERS=1` / `IMAGES=1` compatibility includes raw archive/export and log/attach streaming endpoints. Do not publish that plaintext listener to the host or Internet, and remove the read-exfil opt-in once you migrate to tighter YAML list/inspect rules.

If you run sockguard directly on a host, keep `SOCKGUARD_LISTEN_ADDRESS=127.0.0.1:2375`, configure `listen.tls` for remote TCP, or switch to `SOCKGUARD_LISTEN_SOCKET` to avoid a network listener entirely.

<details>
<summary>Container runtime hardening</summary>

Sockguard runs as UID 65532 (Chainguard `nonroot`) inside the container. On stock Linux Docker hosts where `/var/run/docker.sock` is `0660 root:docker`, add the container to the socket's numeric group ID with `group_add` or run Sockguard as a user/group that can open the socket. For this class of tool, the meaningful hardening levers are the proxy policy, a read-only root filesystem, dropped capabilities, `no-new-privileges`, and the host runtime's seccomp/AppArmor/SELinux confinement.

The examples in this README already opt into the container-level controls sockguard actually benefits from:

- `read_only: true`
- `cap_drop: [ALL]`
- `security_opt: ["no-new-privileges:true"]`

On Linux, one common pattern is:

```yaml
group_add:
  - "${DOCKER_GID:?set this to the numeric group owner of /var/run/docker.sock}"
```

Keep Docker's default seccomp profile or replace it with a stricter custom profile via `security_opt`. On AppArmor or SELinux hosts, keep the runtime's default confinement enabled or replace it with a stricter host policy. If the host runs rootless dockerd, a compromised Docker API client inherits the daemon's reduced authority instead of full host root.

</details>

<details>
<summary>mTLS TCP mode (recommended for remote TCP)</summary>

```yaml
services:
  sockguard:
    image: codeswhat/sockguard:latest
    restart: unless-stopped
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./certs:/certs:ro
    environment:
      - SOCKGUARD_LISTEN_ADDRESS=:2376
      - SOCKGUARD_LISTEN_TLS_CERT_FILE=/certs/server-cert.pem
      - SOCKGUARD_LISTEN_TLS_KEY_FILE=/certs/server-key.pem
      - SOCKGUARD_LISTEN_TLS_CLIENT_CA_FILE=/certs/client-ca.pem
      - SOCKGUARD_INSECURE_ALLOW_READ_EXFILTRATION=true
      - CONTAINERS=1
```

Non-loopback TCP without `listen.tls` fails startup unless you explicitly set `SOCKGUARD_LISTEN_INSECURE_ALLOW_PLAIN_TCP=true`.
Sockguard's server-side TLS minimum for `listen.tls` is TLS 1.3, so remote clients must support TLS 1.3.
If one client CA issues multiple workloads, narrow the trusted set further in YAML with `listen.tls.common_names`, `dns_names`, `ip_addresses`, `uri_sans`, and/or `public_key_sha256_pins` so any CA-issued client cert is not automatically accepted.

</details>

<details>
<summary>Unix socket mode (filesystem-bounded access)</summary>

If you prefer to expose sockguard as a unix socket (no network surface at all), opt in by setting `SOCKGUARD_LISTEN_SOCKET` and sharing the socket via a named volume:

```yaml
services:
  sockguard:
    image: codeswhat/sockguard:latest
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - sockguard-socket:/var/run/sockguard
    environment:
      - SOCKGUARD_LISTEN_SOCKET=/var/run/sockguard/sockguard.sock
      - SOCKGUARD_INSECURE_ALLOW_READ_EXFILTRATION=true
      - CONTAINERS=1

  drydock:
    image: codeswhat/drydock:latest
    depends_on:
      - sockguard
    volumes:
      - sockguard-socket:/var/run/sockguard:ro
    environment:
      - DD_WATCHER_LOCAL_SOCKET=/var/run/sockguard/sockguard.sock

volumes:
  sockguard-socket:
```

Sockguard hardens its own unix socket to `0600` owner-only permissions. `listen.socket_mode` remains in the config surface as a guardrail and must stay `0600`; broader modes are rejected at startup instead of being applied.

To run fully unprivileged with a unix socket, pre-create a host directory with the uid/gid you want and bind-mount it in place of the named volume.

</details>

<hr>

<h2 align="center" id="recent-updates">🆕 Recent Updates</h2>

<details>
<summary><strong>Latest release highlights</strong></summary>

- **v1.2.0 shipped on 2026-06-02** — operational resilience for a wedged daemon. An opt-in **readiness probe** (`health.readiness.*`, default `/ready`) issues a real `GET /containers/json` against the Docker API and returns `503` when the daemon accepts connections but no longer answers — the gap the raw-dial `/health` watchdog misses. An opt-in **`upstream.request_timeout`** bounds finite proxied requests with a total deadline, converting a hung body or heavy read into a fast `504` (`reason_code=upstream_request_timeout`) while exempting streaming and long-lived endpoints. New metrics `sockguard_upstream_api_up` + `sockguard_upstream_readiness_checks_total` mirror the watchdog. The bundled **drydock preset** now allowlists the stock `runc` runtime so drydock recreation stops getting 403'd out of the box. Dependency hygiene: the Go toolchain moves to `1.26.4` (clearing two *reachable* stdlib advisories, GO-2026-5037 / GO-2026-5039), plus the `go-minor` / `npm-minor` / `actions-minor` groups; `govulncheck` reports zero vulnerabilities.
- **v1.1.0 shipped on 2026-06-01** — image-trust verification wired end to end: registry digest resolution, cosign signature discovery (classic tag + OCI 1.1 referrers), digest-pinned forwarding, keyed (PEM) and keyless (Fulcio + Rekor) both enforced, swarm-service create/update now subject to the same image-trust policy as container create. A 21-finding security audit landed alongside: closed request-inspection bypasses (plugin multipart, BuildKit `# syntax=`, gzip bombs, swarm-service capability/sysctl/image-trust escapes), read-side sub-resource visibility gating, new `allowed_runtimes` allowlist, hardened config/admin paths (signed-bundle TOCTOU, PID-only peer rejection, admin-listener CIDR backstop), response redaction extended to `HostConfig.Mounts[].Source` and service `PreviousSpec`. CodeQL `actions` analysis and supply-chain dependency hygiene (`govulncheck` reports zero vulnerabilities) round out the release.
- **v1.0.0 shipped on 2026-05-20** with the public proxy contract locked: YAML schema, CLI flags, env vars, admin endpoints, and Prometheus metric names are now under the v1.x compatibility promise.
- **12 bundled presets** cover drydock, Traefik, Portainer, Watchtower, Homepage, Homarr, Diun, Autoheal, read-only, CIS Docker Benchmark, GitHub Actions self-hosted runner, and GitLab Runner.
- **Expanded QA hardening** added proxy-vs-daemon differential tests, real-dockerd preset conformance, fuzz corpora for routing and visibility, weekly soak testing, and TLS edge-case coverage.
- **Supply-chain verification** covers release images across GHCR, Docker Hub, and Quay.io using the same cosign commands documented for operators.

See [CHANGELOG.md](CHANGELOG.md) for the full itemized history.

</details>

<hr>

<h2 align="center" id="why-sockguard">🤔 Why Sockguard</h2>

The Docker socket is **root access to your host**. Every container with socket access can escape containment, mount the host filesystem, and pivot to other containers. Yet tools like Traefik, Portainer, and drydock need socket access to function.

Most existing socket proxies stop at method/path or regex filtering. Tecnativa and LinuxServer gate broad Docker API sections, wollomatic adds regex allowlists, hostname/IP admission, per-container label allowlists, optional bind-mount restrictions, JSON logging, an active upstream watchdog, and a filtered unix-socket endpoint, 11notes ships a fixed read-only proxy that blocks all writes plus seven exfiltration-prone GET endpoints, and CetusGuard pairs zero-dependency default-deny regex rules with mTLS. We go further on body-aware policy enforcement, per-client profile selection, ownership isolation, and read-side visibility/redaction.

<hr>

<h2 align="center" id="features">✨ Features</h2>

| | Feature | Description |
|---|---|---|
| 🛡️ | **Default-Deny Posture** | Everything blocked unless explicitly allowed. No match means deny. |
| 🎛️ | **Granular Control** | Allow start/stop while blocking create/exec. Per-operation POST controls with glob matching. |
| 📋 | **YAML Configuration** | Declarative rules, glob path patterns, first-match-wins evaluation, and canonical path matching that strips API versions, collapses dot segments, and decodes escaped separators before policy evaluation. 12 bundled workload presets (including CIS Docker Benchmark, self-hosted GitHub Actions runners, and GitLab Runner) plus the default config. |
| 📊 | **Structured Access Logging** | JSON access logs with method, raw path, normalized path, decision, matched rule, latency, canonical request ID, W3C `traceparent` correlation fields, and client info. Use `normalized_path` for SIEM correlation and policy analysis; raw `path` is preserved for forensic replay. Canonical request IDs are generated from a buffered pool so request logging does not block on a fresh entropy read per request. |
| 🔐 | **mTLS for Remote TCP** | Non-loopback TCP listeners require mutual TLS by default. Plaintext TCP is explicit legacy mode only. |
| 🌐 | **Client ACL Primitives** | Optional source-CIDR admission checks, client-container label ACLs, listener certificate selectors (CN/DNS/IP/URI SAN/SPKI), profile certificate selectors (CN/DNS/IP/URI/SPIFFE/SPKI), and unix peer credentials let one proxy differentiate callers before the global rule set runs. When mTLS is enabled, certificate selectors follow the verified client leaf certificate rather than an unverified peer slice entry. |
| 🗃️ | **Bounded Inspect Cache** | Ownership and visibility checks reuse a short-lived singleflight cache for upstream Docker inspect metadata so bursts of repeated reads do not fan out into duplicate synchronous inspect calls. |
| 🔍 | **Request Body Inspection** | `POST /containers/create`, `/containers/*/update`, `/containers/*/exec`, `/exec/*/start`, `PUT /containers/*/archive`, `/images/create`, `/images/load`, `/build`, `/volumes/create`, `/networks/create`, `/networks/*/connect`, `/networks/*/disconnect`, `/secrets/create`, `/configs/create`, `/services/create`, `/services/*/update`, `/swarm/init`, `/swarm/join`, `/swarm/update`, `/swarm/unlock`, `/nodes/*/update`, `/plugins/pull`, `/plugins/*/upgrade`, `/plugins/*/set`, and `/plugins/create` are inspected before Docker sees the request. Sockguard blocks privileged or host-bound workloads, non-allowlisted mounts/devices/commands/remotes, unsafe network/service/swarm/node controls, image archive imports outside registry policy, and unsafe container filesystem archives. `POST /plugins/create` is inspected whether the tar upload arrives as a raw body or `multipart/form-data`. Oversized bodies on bounded JSON/tar inspectors are rejected with `413 Payload Too Large` before any upstream call. These inspectors intentionally decode the policy-relevant subset of Docker's schema and still defer full-schema validation to Docker itself. |
| 🏷️ | **Owner Label Isolation** | A proxy instance can stamp label-capable creates plus build-produced images with an owner label, auto-filter labeled list/prune/events calls, and deny cross-owner access across containers, images, networks, volumes, services, tasks, secrets, configs, nodes, and swarm state. |
| 🫥 | **Visibility-Controlled Reads** | Redacts env, mount, network, config, plugin, and swarm-sensitive metadata by default, can hide labeled list/inspect plus selected service/task log reads behind per-client visibility rules, and keeps raw archive/export and stream-style reads behind explicit opt-in. |
| 🧱 | **Body-Blind Write Guardrail** | Any remaining write Sockguard cannot safely constrain stays behind explicit `insecure_allow_body_blind_writes` opt-in instead of being silently exposed. Today that guardrail chiefly covers arbitrary exec without `request_body.exec.allowed_commands`, `POST /swarm/join` without `request_body.swarm.allowed_join_remote_addrs`, and plugin setting writes without explicit allowed assignment prefixes. |
| 🔄 | **Tecnativa Compatible** | Drop-in replacement for the current Tecnativa env surface, including section vars, `ALLOW_RESTARTS`, `SOCKET_PATH`, and `LOG_LEVEL`. |
| 🎚️ | **Rollout Modes** | Per-profile `mode: enforce\|warn\|audit` lets operators stage a tighter policy without breaking callers. `warn`/`audit` pass-through with `decision=would_deny` on the audit record and a `mode` label on the deny/throttle counters, so dashboards compare blocked vs. would-have-been-blocked volume side by side. |
| 🔁 | **Hot-Reload + Policy Versioning** | `reload.enabled: true` watches the config file via fsnotify (Linux inotify / macOS kqueue) and accepts `SIGHUP`. The new policy goes through the full validator + rule compiler and is atomically swapped behind the running handler; immutable fields (listeners, log, health, metrics, admin, policy-bundle trust material) refuse the reload. A monotonic generation counter is exposed at `GET /admin/policy/version` and via the `sockguard_policy_version` gauge. |
| 🧪 | **Admin API** | Opt-in `POST /admin/validate` accepts a candidate YAML body and returns the same verdict the offline `sockguard validate` command would — perfect for a CI gate before promoting a config. `GET /admin/policy/version` reports `{version, loaded_at, rules, profiles, source, config_sha256, bundle_signer?}`. Both endpoints can ride the main listener or move to a dedicated `admin.listen.*` (socket or TCP, mTLS-aware) firewalled from Docker-API consumers. |
| ✍️ | **Signed Policy Bundles** | `policy_bundle.enabled: true` requires a cosign sigstore bundle to vouch for the YAML config bytes. Keyed (PEM) and keyless (Fulcio + Rekor) trust paths reuse the same sigstore-go stack as image trust. Verification runs at startup before any rule compiles and again on every hot reload — unsigned or tampered bundles abort startup and reject reloads with `reject_signature` on `sockguard_config_reload_total`. The verified signer and YAML digest are stamped on the policy-version snapshot. |
| 🪶 | **Minimal Attack Surface** | Wolfi-based image. Cosign-signed with SBOM and build provenance. |
| ⚡ | **Streaming-Safe** | Preserves Docker streaming endpoints (logs, attach, events) without breaking timeouts, while reaping idle TCP keep-alive connections after 120s. |
| 🩺 | **Health, Watchdog + Readiness** | `/health` endpoint with cached upstream reachability probes, an opt-in active Docker socket watchdog that logs state transitions, and an opt-in `/ready` probe that issues a real `GET /containers/json` against the Docker API — returning `503` when the daemon accepts connections but has stopped answering, the wedged-daemon case a raw socket dial misses. |
| ⏱️ | **Upstream Request Timeout** | Opt-in `upstream.request_timeout` bounds finite proxied requests with a total deadline, turning a hung response body or heavy read into a fast `504` (`reason_code=upstream_request_timeout`). Streaming and long-lived endpoints (events, follow logs/stats, pull/build/push/load, export, attach, container wait) are exempt. |
| 📈 | **Prometheus Metrics** | Opt-in `/metrics` endpoint with low-cardinality request counters, deny counters, latency histograms, active request gauge, upstream watchdog + readiness state/check metrics, plus `sockguard_build_info` and `sockguard_start_time_seconds` gauges for version panels and uptime alerts. |
| 🔗 | **Trace/Log Correlation** | Preserves valid W3C `traceparent` context or generates local context, forwards a proxy-local span ID, and records trace fields in access, audit, and upstream error logs without an OTLP exporter. |
| 🧪 | **Battle-Tested** | 96%+ statement coverage, race-detector clean, monthly Gremlins mutation testing, and fuzz testing on filter, config, proxy, and hijack paths. |

<hr>

<h2 align="center" id="supported-profiles">🔌 Supported Profiles</h2>

### Bundled presets (12)

[drydock](app/configs/drydock.yaml) · [Traefik](app/configs/traefik.yaml) · [Portainer](app/configs/portainer.yaml) · [Watchtower](app/configs/watchtower.yaml) · [Homepage](app/configs/homepage.yaml) · [Homarr](app/configs/homarr.yaml) · [Diun](app/configs/diun.yaml) · [Autoheal](app/configs/autoheal.yaml) · [read-only](app/configs/readonly.yaml) · [CIS Docker Benchmark](app/configs/cis-docker-benchmark.yaml) · [GitHub Actions self-hosted runner](app/configs/github-actions-runner.yaml) · [GitLab Runner](app/configs/gitlab-runner.yaml)

### Ready-to-run compose examples

[drydock](examples/compose/drydock/) · [Traefik](examples/compose/traefik/) · [Portainer](examples/compose/portainer/) · [Watchtower](examples/compose/watchtower/) · [GitHub Actions self-hosted runner](examples/compose/github-actions-runner/) · [GitLab Runner](examples/compose/gitlab-runner/) · [CIS Docker Benchmark gate](examples/compose/cis-docker-benchmark/)

Each example pairs a downstream Docker API consumer with a `sockguard.yaml` overlay and a short README covering audience, exposed API surface, and security tradeoffs.

### Policy surfaces

Rules can cover method/path filters, body-aware write inspection, read-side redaction and visibility, per-client profile selection, rate limits, concurrency caps, owner-label isolation, rollout modes, hot reload, signed policy bundles, and admin validation.

<hr>

<a id="comparison"></a>
<h2 align="center" id="feature-comparison">⚖️ Feature Comparison</h2>

<details>
<summary><strong>How does Sockguard compare to other Docker socket proxies?</strong></summary>

How we stack up against other Docker socket proxies:

| Feature | Tecnativa | LinuxServer | wollomatic | 11notes | CetusGuard | **Sockguard** |
|---------|:---------:|:-----------:|:----------:|:-------:|:----------:|:-------------:|
| Method + path filtering | ✅ | ✅ | ✅ (regex) | Fixed read-only | ✅ (regex) | ✅ |
| Granular container write ops | ❌ | Partial (`ALLOW_*`) | Via regex | ❌ (read-only) | Via regex | ✅ |
| Request body inspection | ❌ | ❌ | Partial (bind-mount source restrictions) | ❌ | ❌ | ✅ (`container` create/update/exec/archive, `image` pull/load, `build`, `volume`, `network` create/connect/disconnect, `secret`, `config`, `service`, `swarm` init/join/update/unlock, `node` update, `plugin`) |
| Per-client admission / policy selection | ❌ | ❌ | Partial (IP/hostname + per-container labels) | ❌ | ❌ | ✅ (CIDR + labels + cert selectors incl. SPKI + unix peer profiles) |
| Read-side visibility / redaction | ❌ | ❌ | ❌ | Partial (blocks 7 risky GETs) | ❌ | ✅ (visibility + protected JSON redaction) |
| Remote TCP mTLS (listener) | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ (TLS 1.3) |
| Remote daemon upstream (TLS) | ❌ | ❌ | ❌ | ❌ | ✅ | Roadmap (v1.3) |
| Structured access logs | ❌ | ❌ | ✅ (JSON option) | ❌ | ❌ | ✅ (request + trace correlation) |
| Dedicated audit log schema | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ (JSON schema + reason codes) |
| Rate limits / concurrency caps | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ (per-profile token-bucket + global priority gate) |
| Rollout modes (audit/warn/enforce) | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ (per-profile shadow + would_deny audit) |
| Hot-reload + policy versioning | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ (fsnotify + SIGHUP, `/admin/policy/version`) |
| Signed policy bundles | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ (sigstore keyed + keyless) |
| YAML config | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Tecnativa env compat | N/A | ✅ | ❌ | ❌ | ❌ | ✅ |

`11notes/docker-socket-proxy` takes a deliberately narrow stance: a fixed read-only proxy that allows every Docker API `GET` except seven exfiltration-prone endpoints (container `attach/ws`, `export`, `archive`, `secrets`/`configs` listing, `swarm/unlockkey`, `images/{name}/get`) and blocks all writes, shipped as a non-root distroless image — we match its read-side blocking with finer-grained per-field redaction and visibility rules, but additionally allow scoped writes instead of refusing them outright. `hectorm/cetusguard` is the closest in spirit to us: a zero-dependency, default-deny proxy with method + regex path rules and mTLS on both the frontend and backend — but it has no request-body inspection, no per-client policies, no owner isolation, no read-side filtering, no metrics, and no hot-reload. Where we go further is body inspection breadth (every body-bearing Docker write path we can safely constrain), named profiles, ownership isolation, and read-side visibility/redaction. CetusGuard, in turn, can dial a remote Docker daemon over backend TLS today — our upstream is the local socket, with remote TCP upstreams on the v1.3 roadmap.

</details>

<hr>

<h2 align="center" id="configuration">⚙️ Configuration</h2>

### Environment Variables (Tecnativa-compatible)

```bash
CONTAINERS=1    # Allow /containers/** (GET/HEAD when POST=0)
IMAGES=0        # Deny /images/**
SERVICES=1      # Allow /services/** (GET/HEAD when POST=0)
EVENTS=1        # Allow /events (default)
POST=0          # Read-only mode

# Granular container writes still work even when POST=0
ALLOW_START=1
ALLOW_STOP=1
ALLOW_RESTARTS=1

# Compat aliases
SOCKET_PATH=/var/run/docker.sock
LOG_LEVEL=warning
```

Compat env vars only generate rules when no explicit `rules:` are configured. If you provide `rules:` in YAML, those rules win even when they happen to match the built-in defaults exactly. Broad compat reads (`CONTAINERS=1`, `IMAGES=1`, `POST=0`) that pull in raw archive/export and log/attach streaming also need `SOCKGUARD_INSECURE_ALLOW_READ_EXFILTRATION=true` — see the [configuration reference](https://getsockguard.com/docs/configuration) for the full env-var surface.

### YAML Config (recommended)

```yaml
listen:
  address: 127.0.0.1:2375   # loopback TCP; use listen.socket or listen.tls for anything else

rules:
  - match: { method: GET, path: "/_ping" }
    action: allow
  - match: { method: GET, path: "/containers/json" }
    action: allow
  - match: { method: GET, path: "/containers/*/json" }
    action: allow
  - match: { method: POST, path: "/containers/*/start" }
    action: allow
  - match: { method: "*", path: "/**" }   # default-deny backstop
    action: deny
```

Trailing `/**` matches both the base path and any deeper path. For example, `/containers/**` matches `/containers` and `/containers/abc/json`.

Sockguard inspects the body of allowed write requests — `containers/create`, `containers/*/update`, `exec`, `build`, `images/create`, `services/create`, `swarm/init`, and the rest of the body-bearing write paths — and blocks privileged or host-bound workloads, non-allowlisted mounts, devices, and registries, and unsafe swarm/network controls. Response bodies are redacted (env, mount paths, topology, secrets) by default. None of that needs configuration to switch on.

Beyond these essentials, every knob is documented in full on the docs site rather than duplicated here:

- **[Configuration reference](https://getsockguard.com/docs/configuration)** — full YAML schema, request-body inspection, mTLS client selectors, per-client ACLs and profiles, rate limiting and concurrency caps, owner-label isolation, rollout modes, hot-reload, signed policy bundles, `insecure_*` opt-ins, response redaction, and config precedence (CLI flags > env vars > config file > defaults).
- **[Admin API](https://getsockguard.com/docs/admin)** — the `POST /admin/validate` CI gate and `GET /admin/policy/version`.
- **[Observability](https://getsockguard.com/docs/observability)** — Prometheus metrics, access/audit log fields, and trace/log correlation.
- **[Security model](https://getsockguard.com/docs/security)** — the defense-in-depth layers and known limitations.

Bundled presets and ready-to-run compose stacks are summarized in [Supported Profiles](#supported-profiles).

<hr>

<h2 align="center" id="cli">🔧 CLI</h2>

```bash
sockguard serve                                     # Start proxy (default)
sockguard validate -c sockguard.yaml                # Validate + print compiled rule table
sockguard match -c sockguard.yaml -X GET --path /v1.45/containers/json
                                                    # Dry-run a single request through the rules
sockguard version                                   # Print version
```

`sockguard match` is the offline rule-evaluation probe — point it
at a config and a `<method, path>` and it prints which rule fires,
what the normalized path looks like, and the reason (if any), so
you can sanity-check a ruleset before any traffic hits the proxy.
Output is text by default or JSON via `-o json`.

<hr>

<a id="migrating-from-tecnativa"></a>
<h2 align="center" id="migration">🔄 Migration</h2>

<details>
<summary><strong>Migrating from Tecnativa or LinuxServer socket proxies</strong></summary>

Replace the image — your current Tecnativa env surface maps over directly, with two explicit security acknowledgements for the non-loopback plaintext TCP listener plus a third for broad archive/export or log/attach streaming parity:

```diff
 services:
   socket-proxy:
-    image: tecnativa/docker-socket-proxy
+    image: codeswhat/sockguard
     volumes:
       - /var/run/docker.sock:/var/run/docker.sock:ro
     environment:
       - SOCKGUARD_LISTEN_ADDRESS=:2375
       - SOCKGUARD_LISTEN_INSECURE_ALLOW_PLAIN_TCP=true
+      - SOCKGUARD_LISTEN_INSECURE_ALLOW_UNAUTHENTICATED_CLIENTS=true
       - SOCKGUARD_INSECURE_ALLOW_READ_EXFILTRATION=true
       - CONTAINERS=1
       - SERVICES=1
       - POST=0
```

LinuxServer's socket-proxy env surface is already Tecnativa-compatible for the broad section toggles Sockguard consumes. For tighter policies, migrate from broad env vars to YAML rules plus body-inspection settings.

</details>

<hr>

<h2 align="center" id="roadmap">🗺️ Roadmap</h2>

<details>
<summary><strong>Version themes & highlights</strong></summary>

**v1.2.0 shipped on 2026-06-02** and is the latest release. **v1.0.0 shipped on 2026-05-20** with the YAML schema, CLI flags, env vars, admin endpoints, and Prometheus metric names under the v1.x compatibility contract. See [CHANGELOG.md](CHANGELOG.md) for the full per-release detail.

### Shipped in v1.2.0

| Track | Surface |
|---|---|
| **Operational resilience** | Opt-in readiness probe (`health.readiness.*`, default `/ready`) that issues a real `GET /containers/json` against the Docker API and returns `503` on a daemon that connects but no longer answers; opt-in `upstream.request_timeout` total per-request deadline that converts a hung body / heavy read into a `504` (`reason_code=upstream_request_timeout`) while exempting streaming and long-lived endpoints; new `sockguard_upstream_api_up` gauge + `sockguard_upstream_readiness_checks_total{result}` counter |
| **Preset fix** | `drydock` preset allowlists the stock `runc` runtime so drydock's recreate-from-inspect updates stop getting 403'd at `POST /containers/create` out of the box |
| **Dependencies** | Go toolchain `1.26.3` → `1.26.4` (builder image + `go.mod` directive), clearing reachable stdlib advisories GO-2026-5037 / GO-2026-5039; `go-minor` group (go-containerregistry, sigstore, protobuf-specs + closure); `npm-minor` group (12, website/docs/tooling); `actions-minor` group (4, SHA-pinned); `govulncheck` reports zero vulnerabilities |

### Shipped in v1.1.0

| Track | Surface |
|---|---|
| **Image trust (end-to-end)** | Registry manifest digest resolution via `internal/imagefetch`; cosign signature discovery (classic `sha256-<digest>.sig` tag + OCI 1.1 referrers); Sigstore bundle reconstruction and digest-binding before verify; keyed (PEM public key) and keyless (Fulcio + Rekor, TUF-fetched trust root) both enforced; `require_rekor_inclusion` defaults to `true` for keyless; verified images digest-pinned (`registry/repo@sha256:…`) before forwarding to close the verify→pull TOCTOU; image-trust policy now also applied to **swarm service create/update** (ContainerSpec) |
| **Security audit (21 findings)** | Plugin multipart-boundary inspection bypass closed; read-side visibility gates container/image sub-resources (logs/stats/top/changes/export/archive/attach, image history/get); new `allowed_runtimes` allowlist for `HostConfig.Runtime`; empty/whitespace exec `User` treated as root; capability-enforcement fixes; BuildKit `# syntax=` directive denial + gzip-bomb decompression cap; swarm services enforce capability allowlist, `allow_sysctls` gate, and image-trust; keyless SAN patterns anchored; `docker load` gzipped archive false-deny fixed; image `/get` export owner-filtered; inspect cache no longer memoizes not-found verdicts; response redaction extended to `HostConfig.Mounts[].Source` and service `PreviousSpec`; signed-bundle verify-then-load TOCTOU closed + env vars cannot override signed policy; PID-only unix-peer profile assignment rejected; dedicated admin TCP listener enforces `clients.allowed_cidrs` |
| **CI / supply chain** | CodeQL `actions` language enabled for workflow static analysis; 20 OSSF Scorecard / Go vuln-DB advisory dependency bumps (x/crypto, x/net, x/sys + closure); `govulncheck` reports zero vulnerabilities |

### Shipped in v1.0.0

| Track | Surface |
|---|---|
| **Foundation** | Default-deny proxy, glob path rules, Tecnativa env compatibility, structured access + audit logging, health endpoint, hardened Wolfi image, multi-arch |
| **Transport** | Unix socket and mTLS-protected TCP listener, TLS 1.3 minimum, loopback by default, SPKI pins, plaintext non-loopback rejected without explicit opt-in |
| **Body inspection** | Every Docker write surface with a meaningful body shape — `containers/create`, exec, build, services, swarm, configs/secrets, volumes, plugins, networks, image load, container update, archive write, node update |
| **Container enforcement** | `Privileged` / host namespaces / `CapAdd` / device passthrough denied by default; `no-new-privileges`, non-root, readonly rootfs, drop-all-capabilities, memory / CPU / PIDs limits, seccomp + AppArmor allowlists; cosign image-trust policy schema and rule compiler (end-to-end enforcement wired in v1.1.0) |
| **Per-client policy** | Source-IP, mTLS (CN/DNS/IP/URI/SPIFFE/SPKI), unix `SO_PEERCRED`, container-label resolution; named profiles with rollout modes (`enforce` / `warn` / `audit`) |
| **Read-side visibility** | Response filtering across containers/services/tasks/configs/secrets/nodes/plugins/swarm/info/system-df with generic protected-JSON mediation |
| **Abuse controls** | Per-client token-bucket rate limits, burst budgets, concurrency caps, endpoint-cost weighting, system-wide priority-aware fairness gate |
| **Observability** | Prometheus `/metrics`, dedicated audit schema, trusted request IDs, deny-reason enums, W3C trace/log correlation, active upstream socket watchdog, lock-free hot path |
| **Dynamic policy** | `POST /admin/validate` CI gate, `fsnotify` + SIGHUP hot reload with immutable-field gate, monotonic policy versioning, optional dedicated admin listener, cosign-signed policy bundles |

### Post-1.0 preview

| Tier | Theme |
|---|---|
| Security hardening (v1.x) | Continued mutation-test hardening of the rule-evaluation core and config validators; swarm `ContainerSpec.User` / `Privileges` enforcement parity with container create; `HostConfig.SecurityOpt` `label=`/`systempaths=` policy evaluation (currently passed through) |
| Policy refinement (v1.x) | Multiple frontend listeners on the main proxy, named rule path aliases |
| Internals (v1.x) | Code-review backlog: collapse the config → filter-options → policy translation layers behind a single source of truth (generated Viper defaults); allocation-free rate-limit bucket state (packed `atomic.Uint64`); profiling-gated JSON redaction fast path; clear per-profile in-flight gauges when a hot reload removes the profile |
| Compliance (v1.x) | CIS Docker Benchmark control mapping, audit-ready policy templates |
| Multi-host (v1.3) | Remote Docker TCP upstreams, multi-upstream fan-out, remote daemon health checking, connection pooling, automatic failover |
| Extensibility (v1.x+) | Optional plugin extension points (WASM or Go plugins), OPA/Rego policy integration |

</details>

<hr>

<h2 align="center" id="documentation">📖 Documentation</h2>

| Resource | Link |
| --- | --- |
| Website | [getsockguard.com](https://getsockguard.com/) |
| Docs | [getsockguard.com/docs](https://getsockguard.com/docs) |
| Getting Started | [Getting Started](https://getsockguard.com/docs/getting-started) |
| Configuration | [Configuration](https://getsockguard.com/docs/configuration) |
| Presets | [Presets](https://getsockguard.com/docs/presets) |
| Migration | [Migration](https://getsockguard.com/docs/migration) |
| CIS Docker Benchmark | [CIS Docker Benchmark](https://getsockguard.com/docs/cis-docker-benchmark) |
| Admin API | [Admin API](https://getsockguard.com/docs/admin) |
| Observability | [Observability](https://getsockguard.com/docs/observability) |
| Security Model | [Security Model](https://getsockguard.com/docs/security) |
| Image Verification | [Image Verification](https://getsockguard.com/docs/verification) |
| Changelog | [`CHANGELOG.md`](CHANGELOG.md) |
| Contributing | [`CONTRIBUTING.md`](CONTRIBUTING.md) |
| Security Policy | [`SECURITY.md`](SECURITY.md) |
| Issues | [GitHub Issues](https://github.com/CodesWhat/sockguard/issues) |
| Discussions | [GitHub Discussions](https://github.com/CodesWhat/sockguard/discussions) |

<hr>

<a id="star-history"></a>

<div align="center">
  <a href="https://star-history.com/#CodesWhat/sockguard&Date">
    <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=CodesWhat/sockguard&type=Date" />
  </a>
</div>

---

<div align="center">

[![SemVer](https://img.shields.io/badge/semver-2.0.0-blue)](https://semver.org/)
[![Conventional Commits](https://img.shields.io/badge/commits-conventional-fe5196?logo=conventionalcommits&logoColor=fff)](https://www.conventionalcommits.org/)
[![Keep a Changelog](https://img.shields.io/badge/changelog-Keep%20a%20Changelog-E05735)](https://keepachangelog.com/)

### Built With

[![Go 1.26](https://img.shields.io/badge/Go_1.26-00ADD8?logo=go&logoColor=fff)](https://go.dev/)
[![Cobra](https://img.shields.io/badge/Cobra-00ADD8?logo=go&logoColor=fff)](https://github.com/spf13/cobra)
[![Viper](https://img.shields.io/badge/Viper-00ADD8?logo=go&logoColor=fff)](https://github.com/spf13/viper)
[![fsnotify](https://img.shields.io/badge/fsnotify-00ADD8?logo=go&logoColor=fff)](https://github.com/fsnotify/fsnotify)
[![Sigstore](https://img.shields.io/badge/Sigstore-FFC107?logo=sigstore&logoColor=000)](https://www.sigstore.dev/)
[![Wolfi](https://img.shields.io/badge/Wolfi-4A4A55?logo=chainguard&logoColor=fff)](https://edu.chainguard.dev/open-source/wolfi/overview/)
[![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=fff)](https://www.docker.com/)
[![GoReleaser](https://img.shields.io/badge/GoReleaser-00ADD8?logo=go&logoColor=fff)](https://goreleaser.com/)
<br>
[![Next.js](https://img.shields.io/badge/Next.js-000000?logo=nextdotjs&logoColor=fff)](https://nextjs.org/)
[![Fumadocs](https://img.shields.io/badge/Fumadocs-000000?logo=nextdotjs&logoColor=fff)](https://fumadocs.dev/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-06B6D4?logo=tailwindcss&logoColor=fff)](https://tailwindcss.com/)
[![Turborepo](https://img.shields.io/badge/Turborepo-EF4444?logo=turborepo&logoColor=fff)](https://turbo.build/repo)
[![Biome](https://img.shields.io/badge/Biome_2-60a5fa?logo=biome&logoColor=fff)](https://biomejs.dev/)

### Community & Support

Issues, ideas, and pull requests are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md), use [SECURITY.md](SECURITY.md) for private vulnerability disclosure, and use [GitHub Discussions](https://github.com/CodesWhat/sockguard/discussions) for design questions.

For local fuzz triage, run `scripts/local-fuzz.sh --suite ci --fuzztime 2m`. Use `--suite ultra` for every fuzzer, `--timeout` to set the Go watchdog explicitly, and `--docker --platform linux/amd64` when you want closer GitHub Actions parity.

Every release image is cosign-signed via GitHub Actions OIDC. Before running a sockguard image in production, verify it with the canonical invocation in the [image verification guide](https://getsockguard.com/docs/verification).

**[Apache-2.0 License](LICENSE)**

Built by <a href="https://codeswhat.com">CodesWhat</a>

[![Ko-fi](https://img.shields.io/badge/Ko--fi-Support-ff5e5b?logo=kofi&logoColor=white)](https://ko-fi.com/codeswhat)
[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?logo=buymeacoffee&logoColor=black)](https://buymeacoffee.com/codeswhat)
[![Sponsor](https://img.shields.io/badge/Sponsor-ea4aaa?logo=githubsponsors&logoColor=white)](https://github.com/sponsors/CodesWhat)

<a href="#sockguard">Back to top</a>

</div>
