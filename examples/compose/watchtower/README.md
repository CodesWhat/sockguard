# Sockguard + Watchtower

**Who this is for:** Teams running Watchtower for automatic container updates and wanting to eliminate the raw Docker socket mount from the Watchtower container.

**What's exposed:** Sockguard listens on plaintext TCP `:2375` on the private Docker compose network. Watchtower connects via `DOCKER_HOST=tcp://sockguard:2375`. The port is **not** published to the host.

## Why TCP instead of unix socket

Watchtower's `DOCKER_HOST` environment variable accepts `unix://` paths, but the container does not have access to the host filesystem. TCP over the compose-internal bridge network is the standard pattern for Tecnativa-compatible Watchtower deployments and keeps the migration path simple.

## Security tradeoffs

| Control | Status |
|---|---|
| sockguard: `read_only`, `cap_drop: ALL`, `no-new-privileges` | Enabled |
| No raw socket in Watchtower container | Yes — TCP to sockguard only |
| Port 2375 exposed to host | No — compose-internal network only |
| Exec write guard | Disabled — `insecure_allow_body_blind_writes: true` for lifecycle hooks |
| Raw log/archive streams | Enabled — `insecure_allow_read_exfiltration: true` for compatibility |
| Image pulls | All registries allowed (Watchtower tracks arbitrary images) |

## Usage

```bash
docker compose up -d
```

## Hardening tips

- If your Watchtower lifecycle hooks are fixed commands, replace `insecure_allow_body_blind_writes: true` with `request_body.exec.allowed_commands` listing the exact argv vectors.
- Add `clients.allowed_cidrs` to restrict which source IPs can reach the sockguard TCP listener within the Docker network.
- Switch to mTLS TCP (`listen.tls`) for stronger in-network authentication if your Watchtower image supports it.
