# Sockguard + Homarr

**Who this is for:** Teams running [Homarr](https://homarr.dev) with its Docker integration (container status, start/stop/restart/remove from the dashboard) and wanting to eliminate the raw Docker socket mount.

**What's exposed:** Sockguard listens on plaintext TCP `:2375` on the private Docker compose network. Homarr connects via `DOCKER_HOSTNAMES=sockguard` and `DOCKER_PORTS=2375`. The port is **not** published to the host. The Homarr UI is on port 7575.

## Why TCP instead of unix socket

Homarr's Docker integration is configured with a hostname and port pair, not a socket path, so the proxy has to be reachable over TCP on the compose-internal network.

## Security tradeoffs

| Control | Status |
|---|---|
| sockguard: `read_only`, `cap_drop: ALL`, `no-new-privileges` | Enabled |
| No raw socket in Homarr container | Yes — TCP to sockguard only |
| Port 2375 exposed to host | No — compose-internal network only |
| Container list, inspect, stats | Allowed |
| Container start, stop, restart, remove | Allowed |
| Container logs | Allowed — `insecure_allow_read_exfiltration: true` required for the log view |
| Create, exec, image, network, volume writes | Denied |

## Usage

Set the Docker socket's group GID so sockguard can open `/var/run/docker.sock` (Linux: `stat -c '%g'`; macOS: `stat -f '%g'`):

```bash
case "$(uname -s)" in
  Linux) export DOCKER_SOCK_GID="$(stat -c '%g' /var/run/docker.sock)" ;;
  Darwin) export DOCKER_SOCK_GID="$(stat -f '%g' /var/run/docker.sock)" ;;
  *) echo "Unsupported host OS" >&2; exit 1 ;;
esac
export HOMARR_SECRET_ENCRYPTION_KEY="$(openssl rand -hex 32)"
docker compose up -d
# Homarr: http://localhost:7575
```

Keep `HOMARR_SECRET_ENCRYPTION_KEY` stable across restarts, or Homarr cannot decrypt the integration secrets it already stored.

## Hardening tips

- Add `clients.allowed_cidrs` to restrict which source IPs can reach the sockguard TCP listener within the Docker network.
- Drop `DELETE /containers/*` from the rules if you don't want dashboard users removing containers.
- Switch to mTLS TCP (`listen.tls`) for stronger in-network authentication if your Homarr deployment supports client certificates.
