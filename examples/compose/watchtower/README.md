# Sockguard + Watchtower

**Who this is for:** Teams running [Watchtower](https://github.com/nicholas-fedor/watchtower) for automatic container updates and wanting to eliminate the raw Docker socket mount from the Watchtower container.

**What's exposed:** Sockguard listens on plaintext TCP `:2375` on the private Docker compose network. Watchtower connects via `DOCKER_HOST=tcp://sockguard:2375`. The port is **not** published to the host.

## Why TCP instead of unix socket

Watchtower's `DOCKER_HOST` environment variable accepts `unix://` paths, but the container does not have access to the host filesystem. TCP over the compose-internal bridge network is the standard pattern for Tecnativa-compatible Watchtower deployments and keeps the migration path simple.

## Security tradeoffs

| Control | Status |
|---|---|
| sockguard: `read_only`, `cap_drop: ALL`, `no-new-privileges` | Enabled |
| No raw socket in Watchtower container | Yes — TCP to sockguard only |
| Port 2375 exposed to host | No — compose-internal network only |
| Exec command allowlist | Disabled — `insecure_allow_body_blind_writes: true` acknowledges arbitrary lifecycle hooks |
| Raw log/archive/image-export streams | Denied — no read-exfiltration acknowledgment |
| Image pulls | All registries allowed (Watchtower tracks arbitrary images) |
| Image list | Denied — Watchtower v1.21.2 inspects images directly |

## Usage

Set the Docker socket's group GID so sockguard can open `/var/run/docker.sock` (Linux: `stat -c '%g'`; macOS: `stat -f '%g'`):

```bash
case "$(uname -s)" in
  Linux) export DOCKER_SOCK_GID="$(stat -c '%g' /var/run/docker.sock)" ;;
  Darwin) export DOCKER_SOCK_GID="$(stat -f '%g' /var/run/docker.sock)" ;;
  *) echo "Unsupported host OS" >&2; exit 1 ;;
esac
docker compose up -d
```

## Hardening tips

- If your Watchtower lifecycle hooks are fixed commands, replace `insecure_allow_body_blind_writes: true` with `request_body.exec.allowed_commands` listing the exact argv vectors. Set `request_body.exec.allow_root_user: false` too if every hook selects a non-root user explicitly.
- Add `clients.allowed_cidrs` to restrict which source IPs can reach the sockguard TCP listener within the Docker network.
- Switch to mTLS TCP (`listen.tls`) for stronger in-network authentication if your Watchtower image supports it.
