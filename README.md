<div align="center">

<img src="sockguard-logo.png" alt="sockguard" width="180">

<h1>sockguard</h1>

**Control what gets through. A security-first Docker socket proxy built in Go.**

</div>

<p align="center">
  <a href="https://github.com/CodesWhat/sockguard/releases"><img src="https://img.shields.io/github/v/release/CodesWhat/sockguard?include_prereleases&label=release" alt="Release"></a>
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
</p>

<p align="center">
  <a href="https://github.com/CodesWhat/sockguard/actions/workflows/ci-verify.yml"><img src="https://github.com/CodesWhat/sockguard/actions/workflows/ci-verify.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="https://goreportcard.com/report/github.com/CodesWhat/sockguard"><img src="https://goreportcard.com/badge/github.com/CodesWhat/sockguard" alt="Go Report Card"></a>
  <a href="https://pkg.go.dev/github.com/CodesWhat/sockguard"><img src="https://pkg.go.dev/badge/github.com/CodesWhat/sockguard.svg" alt="Go Reference"></a>
  <br>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/CodesWhat/sockguard"><img src="https://img.shields.io/ossf-scorecard/github.com/CodesWhat/sockguard?label=openssf+scorecard&style=flat" alt="OpenSSF Scorecard"></a>
</p>

<hr>

<h2 align="center">📑 Contents</h2>

- [📖 Documentation](https://docs.getsockguard.com)
- [🌐 Website](https://getsockguard.com)
- [🚀 Quick Start](#quick-start)
- [🤔 Why Sockguard](#why-sockguard)
- [✨ Features](#features)
- [⚖️ Comparison](#comparison)
- [⚙️ Configuration](#configuration)
- [🔧 CLI](#cli)
- [🔄 Migrating from Tecnativa](#migrating-from-tecnativa)
- [🗺️ Roadmap](#roadmap)
- [🛠️ Built With](#built-with)
- [🤝 Contributing](#contributing)
- [🔒 Security](#security)

<hr>

> [!WARNING]
> **Pre-release software.** Sockguard is in active development. APIs, rule formats, and CLI flags may change before v1.0.

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

The compose example above opts into **legacy plaintext TCP** with `SOCKGUARD_LISTEN_INSECURE_ALLOW_PLAIN_TCP=true` so migration from `tecnativa/docker-socket-proxy` and `linuxserver/socket-proxy` still works on a private Docker network. Do not publish that plaintext listener to the host or Internet.

If you run sockguard directly on a host, keep `SOCKGUARD_LISTEN_ADDRESS=127.0.0.1:2375`, configure `listen.tls` for remote TCP, or switch to `SOCKGUARD_LISTEN_SOCKET` to avoid a network listener entirely.

<details>
<summary>Container runtime hardening</summary>

Sockguard runs as root inside the container by default so it can open `/var/run/docker.sock` on stock Docker hosts without `user` or `group_add` overrides. For this class of tool, the meaningful hardening levers are the proxy policy, a read-only root filesystem, dropped capabilities, `no-new-privileges`, and the host runtime's seccomp/AppArmor/SELinux confinement.

The examples in this README already opt into the container-level controls sockguard actually benefits from:

- `read_only: true`
- `cap_drop: [ALL]`
- `security_opt: ["no-new-privileges:true"]`

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
      - CONTAINERS=1
```

Non-loopback TCP without `listen.tls` fails startup unless you explicitly set `SOCKGUARD_LISTEN_INSECURE_ALLOW_PLAIN_TCP=true`.
Sockguard's server-side TLS minimum for `listen.tls` is TLS 1.3, so remote clients must support TLS 1.3.

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

To run fully unprivileged with a unix socket, pre-create a host directory with the uid/gid you want and bind-mount it in place of the named volume.

</details>

<hr>

<h2 align="center" id="why-sockguard">🤔 Why Sockguard</h2>

The Docker socket is **root access to your host**. Every container with socket access can escape containment, mount the host filesystem, and pivot to other containers. Yet tools like Traefik, Portainer, and drydock need socket access to function.

Existing socket proxies (Tecnativa, LinuxServer) filter by URL path only. Sockguard goes further: granular operation control, structured audit logging, and a default-deny posture out of the box.

<hr>

<h2 align="center" id="features">✨ Features</h2>

| | Feature | Description |
|---|---|---|
| 🛡️ | **Default-Deny Posture** | Everything blocked unless explicitly allowed. No match means deny. |
| 🎛️ | **Granular Control** | Allow start/stop while blocking create/exec. Per-operation POST controls with glob matching. |
| 📋 | **YAML Configuration** | Declarative rules, glob path patterns, first-match-wins evaluation. 10 bundled presets. |
| 📊 | **Structured Logging** | JSON access logs with method, path, decision, matched rule, latency, client info. |
| 🔐 | **mTLS for Remote TCP** | Non-loopback TCP listeners require mutual TLS by default. Plaintext TCP is explicit legacy mode only. |
| 🌐 | **Client ACL Primitives** | Optional source-CIDR admission checks and client-container label ACLs let one proxy differentiate TCP callers before the global rule set runs. |
| 🔍 | **Request Body Inspection** | `POST /containers/create` bodies are inspected to block privileged containers, host networking, and non-allowlisted bind mounts before Docker sees the request. |
| 🏷️ | **Owner Label Isolation** | A proxy instance can stamp containers, networks, volumes, and build-produced images with an owner label, auto-filter list/prune/events calls, and deny cross-owner access to labeled resources. |
| 🫥 | **Response Filtering** | Redacts `Config.Env` and mount-path metadata on common Docker read endpoints by default so allowlisted readers do not inherit raw host topology or runtime secret exposure. |
| 🧱 | **Body-Blind Write Guardrail** | Remaining body-sensitive write endpoints such as `exec`, `build`, and Swarm writes still require explicit unsafe opt-in until their request bodies are inspected. |
| 🔄 | **Tecnativa Compatible** | Drop-in replacement using the same env vars. `CONTAINERS=1`, `POST=0`, `ALLOW_START=1` all work. |
| 🪶 | **Minimal Attack Surface** | Wolfi-based image, ~12MB. Cosign-signed with SBOM and build provenance. |
| ⚡ | **Streaming-Safe** | Preserves Docker streaming endpoints (logs, attach, events) without breaking timeouts, while reaping idle TCP keep-alive connections after 120s. |
| 🩺 | **Health Check** | `/health` endpoint with cached upstream reachability probes. |
| 🧪 | **Battle-Tested** | ~99% statement coverage, race-detector clean, fuzz testing on filter, config, proxy, and hijack paths. |

<hr>

<h2 align="center" id="comparison">⚖️ Comparison</h2>

How sockguard stacks up against other Docker socket proxies:

| Feature | Tecnativa | LinuxServer | wollomatic | **Sockguard** |
|---------|:---------:|:-----------:|:----------:|:-------------:|
| Method + path filtering | ✅ | ✅ | ✅ | ✅ |
| Granular POST ops | ❌ | Partial | Via regex | ✅ |
| Request body inspection | ❌ | ❌ | ❌ | ✅ (`/containers/create`) |
| Per-client policies | ❌ | ❌ | CIDR + client labels | ✅ (CIDR + client labels) |
| Response filtering | ❌ | ❌ | ❌ | ✅ (env + mount redaction) |
| Structured audit log | ❌ | ❌ | ❌ | ✅ |
| YAML config | ❌ | ❌ | ❌ | ✅ |
| Tecnativa env compat | N/A | ✅ | ❌ | ✅ |

<hr>

<h2 align="center" id="configuration">⚙️ Configuration</h2>

### Environment Variables (Tecnativa-compatible)

```bash
CONTAINERS=1    # Allow GET /containers/**
IMAGES=0        # Deny /images/**
EVENTS=1        # Allow GET /events
POST=0          # Read-only mode

# Granular (requires POST=1)
ALLOW_START=1
ALLOW_STOP=1
ALLOW_CREATE=0
ALLOW_EXEC=0
```

Compat env vars only generate rules when no explicit `rules:` are configured. If you provide `rules:` in YAML, those rules win even when they happen to match the built-in defaults exactly.

### YAML Config (recommended)

```yaml
listen:
  address: 127.0.0.1:2375
  insecure_allow_plain_tcp: false
  tls:
    cert_file: /run/secrets/sockguard/server-cert.pem
    key_file: /run/secrets/sockguard/server-key.pem
    client_ca_file: /run/secrets/sockguard/client-ca.pem

insecure_allow_body_blind_writes: false

response:
  deny_verbosity: minimal  # recommended for production; verbose adds method/path/reason for debugging
  redact_container_env: true
  redact_mount_paths: true

request_body:
  container_create:
    allowed_bind_mounts:
      - /srv/containers
      - /var/lib/app-data

clients:
  allowed_cidrs:
    - 172.18.0.0/16
  container_labels:
    enabled: true
    label_prefix: com.sockguard.allow.

ownership:
  owner: ci-job-123
  label_key: com.sockguard.owner

rules:
  - match: { method: GET, path: "/_ping" }
    action: allow
  - match: { method: GET, path: "/containers/**" }
    action: allow
  - match: { method: POST, path: "/containers/*/start" }
    action: allow
  - match: { method: "*", path: "/**" }
    action: deny
```

Trailing `/**` matches both the base path and any deeper path. For example, `/containers/**` matches `/containers` and `/containers/abc/json`.

`listen.tls` is only needed when you expose Sockguard on non-loopback TCP. Plaintext non-loopback TCP is rejected unless you set `listen.insecure_allow_plain_tcp: true`, which is intended only for legacy compatibility on a private, trusted network.

Allowed `POST /containers/create` requests are inspected by default. Unless you opt out, Sockguard blocks `HostConfig.Privileged=true`, `HostConfig.NetworkMode=host`, and any bind mount source outside `request_body.container_create.allowed_bind_mounts`. Named volumes still work without allowlist entries because they are not host bind mounts.

`clients.allowed_cidrs` is a coarse TCP-client gate. Requests whose source IP falls outside every configured CIDR are denied before `/health` or the global rule set runs.

When `clients.container_labels.enabled` is true, Sockguard resolves bridge-network callers by source IP through the Docker API and looks for per-client allow labels on the calling container. Each `clients.container_labels.label_prefix + <method>` label is interpreted as a comma-separated Sockguard glob allowlist for that HTTP method. For example, `com.sockguard.allow.get=/containers/**,/events` allows only `GET /containers/**` and `GET /events` for that client. If you are migrating from wollomatic, set `clients.container_labels.label_prefix: socket-proxy.allow.` to reuse existing labels.

Set `ownership.owner` to turn on per-proxy resource ownership isolation. Sockguard will add `ownership.label_key=ownership.owner` labels to container, network, and volume creates, add the same label to `POST /build`, inject owner label filters into list/prune/events requests, and deny direct access to labeled resources owned by some other proxy instance. Unowned images are still readable by default so shared base images can be pulled and inspected without relabeling.

`insecure_allow_body_blind_writes` is off by default. If your rule set allows the remaining body-sensitive Docker write endpoints such as `POST /containers/*/exec`, `POST /exec/*/start`, `POST /build`, or Swarm service creation/update, validation fails unless you explicitly set this flag to `true`. That opt-in acknowledges that Sockguard is still enforcing method+path only for those writes.

`response.deny_verbosity` defaults to `minimal` so `403` responses carry only a generic deny message and never leak the request method, path, or matched rule reason back to the caller. Set it to `verbose` explicitly during rule authoring if you need to see which rule denied a request — verbose is still useful in dev but should never run in production because it echoes request details in the response body. Even in `verbose` mode, Sockguard redacts denied `/secrets/*` and `/swarm/unlockkey` paths before returning them.

`response.redact_container_env` and `response.redact_mount_paths` also default to `true`. Sockguard now scrubs `Config.Env` on `GET /containers/*/json`, redacts `HostConfig.Binds` host paths plus `Mounts[*].Source` on container list/inspect responses, and redacts `Mountpoint` on volume list/inspect responses. Disable either toggle only for trusted admin clients that genuinely need raw Docker metadata.

Preset configs included for [drydock](app/configs/drydock.yaml), [Traefik](app/configs/traefik.yaml), [Portainer](app/configs/portainer.yaml), [Watchtower](app/configs/watchtower.yaml), [Homepage](app/configs/homepage.yaml), [Homarr](app/configs/homarr.yaml), [Diun](app/configs/diun.yaml), [Autoheal](app/configs/autoheal.yaml), and [read-only](app/configs/readonly.yaml).

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

<h2 align="center" id="migrating-from-tecnativa">🔄 Migrating from Tecnativa</h2>

Replace the image — your env vars work as-is:

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
       - CONTAINERS=1
       - POST=0
```

<hr>

<h2 align="center" id="roadmap">🗺️ Roadmap</h2>

| Version | Theme | Status |
|---------|-------|--------|
| **0.1.0** | MVP — drop-in replacement with granular control, YAML config, structured logging | ✅ shipped |
| **0.2.0** | mTLS for remote TCP, TLS 1.3 minimum, loopback-by-default listener, body-blind write guardrail | ✅ shipped |
| **0.3.0** | Request-body inspection for `/containers/create`, per-proxy owner labels, per-client CIDR + container-label ACLs | ✅ shipped |
| **0.4.0** | Named per-client policy profiles, body inspection for `/build` and `exec`, expanded response filtering (visibility rules, network redaction) | 🕒 planned |
| **0.5.0** | Observability — Prometheus metrics, audit log persistence, OTel trace/span IDs in log records | 🕒 planned |
| **0.6.0** | Rate limiting, policy safety rails, security enforcement | 🕒 planned |

<hr>

<h2 align="center" id="built-with">🛠️ Built With</h2>

<p align="center">
  <img src="https://img.shields.io/badge/Go-00ADD8?logo=go&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/Cobra-00ADD8?logo=go&logoColor=white" alt="Cobra">
  <img src="https://img.shields.io/badge/Viper-00ADD8?logo=go&logoColor=white" alt="Viper">
  <img src="https://img.shields.io/badge/Wolfi-4A4A55?logo=chainguard&logoColor=white" alt="Wolfi">
  <img src="https://img.shields.io/badge/Cosign-FFC107?logo=sigstore&logoColor=black" alt="Cosign">
  <br>
  <img src="https://img.shields.io/badge/Next.js-000000?logo=nextdotjs&logoColor=white" alt="Next.js">
  <img src="https://img.shields.io/badge/Nextra-000000?logo=nextdotjs&logoColor=white" alt="Nextra">
  <img src="https://img.shields.io/badge/Tailwind-06B6D4?logo=tailwindcss&logoColor=white" alt="Tailwind">
  <img src="https://img.shields.io/badge/Turborepo-EF4444?logo=turborepo&logoColor=white" alt="Turborepo">
  <img src="https://img.shields.io/badge/Biome-60A5FA?logo=biome&logoColor=white" alt="Biome">
</p>

<hr>

<h2 align="center" id="contributing">🤝 Contributing</h2>

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues, ideas, and pull requests welcome.

<hr>

<h2 align="center" id="security">🔒 Security</h2>

- **Responsible disclosure** — see [SECURITY.md](SECURITY.md) for scope, supported versions, and how to report a vulnerability privately.
- **Image verification** — every release is cosign-signed via GitHub Actions OIDC. Before running a sockguard image in production, verify it with the canonical invocation in the [image verification guide](docs/src/content/verification.mdx).

<div align="center">

Built by <a href="https://codeswhat.com">CodesWhat</a> · Licensed under <a href="LICENSE">Apache-2.0</a>

</div>
