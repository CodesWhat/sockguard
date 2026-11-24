# Sockguard + Dozzle

**Who this is for:** Teams running [Dozzle](https://dozzle.dev) for its default read-only view (container list, live logs, stats, events) and wanting to eliminate the raw Docker socket mount.

**What's exposed:** Sockguard listens on plaintext TCP `:2375` on the private Docker compose network. Dozzle connects via `DOCKER_HOST=tcp://sockguard:2375`. The port is **not** published to the host. The Dozzle UI is on port 8080.

## Why TCP instead of unix socket

Dozzle reads its Docker endpoint from `DOCKER_HOST`, and the proxy has to be reachable over TCP on the compose-internal network.

## Security tradeoffs

| Control | Status |
|---|---|
| sockguard: `read_only`, `cap_drop: ALL`, `no-new-privileges` | Enabled |
| No raw socket in Dozzle container | Yes, TCP to sockguard only |
| Port 2375 exposed to host | No, compose-internal network only |
| Container list, inspect, stats, events | Allowed |
| Ping, version, info | Allowed |
| Container logs | Allowed, `insecure_allow_read_exfiltration: true` required for the log view |
| Start, stop, restart, remove (`DOZZLE_ENABLE_ACTIONS`) | Denied |
| Exec and attach (`DOZZLE_ENABLE_SHELL`) | Denied |
| Create, image, network, volume writes, disk usage, Swarm reads | Denied |

## Not supported

Container actions and the shell (`DOZZLE_ENABLE_ACTIONS`, `DOZZLE_ENABLE_SHELL`) are not supported by this preset. Sockguard refuses the calls they make, so turning them on gives you buttons that fail. Swarm mode and agent mode are untested.

## Behavior notes

- Mount paths and network addresses stay redacted (the sockguard defaults), so Dozzle's container details show placeholders or empty values for them. Container env is redacted too, and Dozzle doesn't read it.
- Dozzle's volume and disk-size readings come from `GET /system/df`, which this preset denies. Dozzle logs the failure and carries on without those figures.
- Derived from Dozzle v11.5.0 (`internal/container/docker/client.go`). Check the preset against the Dozzle source again when you bump the pinned image.

## Usage

Set the Docker socket's group GID so sockguard can open `/var/run/docker.sock` (Linux: `stat -c '%g'`; macOS: `stat -f '%g'`):

```bash
case "$(uname -s)" in
  Linux) export DOCKER_SOCK_GID="$(stat -c '%g' /var/run/docker.sock)" ;;
  Darwin) export DOCKER_SOCK_GID="$(stat -f '%g' /var/run/docker.sock)" ;;
  *) echo "Unsupported host OS" >&2; exit 1 ;;
esac
docker compose up -d
# Dozzle: http://localhost:8080
```

## Hardening tips

- Add `clients.allowed_cidrs` to restrict which source IPs can reach the sockguard TCP listener within the Docker network.
- Put Dozzle behind its own authentication (`DOZZLE_AUTH_PROVIDER`). Anyone who can open the UI can read every container's logs.
- Switch to mTLS TCP (`listen.tls`) for stronger in-network authentication if your Dozzle deployment supports client certificates.
