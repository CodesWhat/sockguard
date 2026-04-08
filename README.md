# sockguard

A Docker socket proxy that actually inspects what it proxies.

> **Status**: Pre-release. v0.1.0 in development.

## Why

The Docker socket is root access to your host. Every container with socket access can escape containment. Yet tools like Traefik, Portainer, and drydock need socket access to function.

Existing proxies filter by URL path only. Sockguard goes further: granular operation control, request body inspection, per-client policies, and structured audit logging.

## Features

| Feature | Tecnativa | LinuxServer | wollomatic | Sockguard |
|---------|-----------|-------------|-----------|-----------|
| Method + path filtering | Yes | Yes | Yes | Yes |
| Granular POST ops | No | Partial | Via regex | Yes |
| Request body inspection | No | No | No | Planned |
| Per-client policies | No | No | IP only | Planned |
| Response filtering | No | No | No | Planned |
| Structured audit log | No | No | No | Yes |
| YAML config | No | No | No | Yes |
| Tecnativa env compat | N/A | Yes | No | Yes |

## Quick Start

```yaml
# docker-compose.yml
services:
  sockguard:
    image: codeswhat/sockguard:latest
    restart: unless-stopped
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - sockguard-socket:/var/run/sockguard
    environment:
      - CONTAINERS=1
      - IMAGES=1
      - EVENTS=1

  # Your app connects to the proxy socket instead of docker.sock
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

## Configuration

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

### YAML Config (recommended)

```yaml
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

Preset configs included for [drydock](app/configs/drydock.yaml), [Traefik](app/configs/traefik.yaml), [Portainer](app/configs/portainer.yaml), [Watchtower](app/configs/watchtower.yaml), [Homepage](app/configs/homepage.yaml), [Homarr](app/configs/homarr.yaml), [Diun](app/configs/diun.yaml), [Autoheal](app/configs/autoheal.yaml), and [read-only](app/configs/readonly.yaml).

## CLI

```bash
sockguard serve                           # Start proxy (default)
sockguard validate -c sockguard.yaml      # Validate config
sockguard version                         # Print version
```

## Operational Notes

- `sockguard` keeps Go `http.Server.ReadTimeout` at `0` to preserve Docker streaming endpoints (for example attach, logs follow, and events).
- `sockguard` sets `http.Server.ReadHeaderTimeout` to `5s` as a partial slowloris mitigation while leaving streaming request bodies untouched.
- Tradeoff: on TCP listeners this still leaves long-lived request bodies and connections more exposed than a fully bounded read timeout would.
- `/health` caches upstream socket reachability for `2s` to avoid opening a fresh Unix socket on every liveness probe.
- Recommended deployment: Unix socket where possible, otherwise bind to private interfaces and place Sockguard behind a reverse proxy/load balancer that enforces request-header and read timeouts.

## Migrating from Tecnativa

Replace the image — your env vars work as-is:

```diff
 services:
   socket-proxy:
-    image: tecnativa/docker-socket-proxy
+    image: codeswhat/sockguard
     volumes:
       - /var/run/docker.sock:/var/run/docker.sock:ro
     environment:
       - CONTAINERS=1
       - POST=0
```

## Roadmap

| Version | Theme |
|---------|-------|
| **0.1.0** | MVP — drop-in replacement with granular control, YAML config, structured logging |
| **0.2.0** | Request body inspection — block privileged containers, dangerous mounts |
| **0.3.0** | Per-client policy profiles — one proxy, many consumers |
| **0.4.0** | Response filtering — hide containers, redact env vars |
| **0.5.0** | Prometheus metrics + audit logging |
| **0.6.0** | mTLS, rate limiting, security enforcement |

## Built With

Go, Cobra, Viper, Wolfi (Chainguard), Turborepo, Next.js, Nextra

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).
