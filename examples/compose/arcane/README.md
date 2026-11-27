# Sockguard + Arcane

**Who this is for:** Teams running [Arcane](https://github.com/getarcaneapp/arcane) as a read-only view of their Docker host (dashboard, containers, images, volumes, networks, logs) and wanting to eliminate the raw Docker socket mount.

**What's exposed:** Sockguard listens on plaintext TCP `:2375` on the private Docker compose network. Arcane connects via `DOCKER_HOST=tcp://sockguard:2375`. The port is **not** published to the host. The Arcane UI is on port 3552.

## Why TCP instead of unix socket

Arcane reads its Docker endpoint from `DOCKER_HOST`, and the proxy has to be reachable over TCP on the compose-internal network.

## Security tradeoffs

| Control | Status |
|---|---|
| sockguard: `read_only`, `cap_drop: ALL`, `no-new-privileges` | Enabled |
| No raw socket in Arcane container | Yes, TCP to sockguard only |
| Port 2375 exposed to host | No, compose-internal network only |
| Container list, inspect, stats, top, events | Allowed |
| Image list, inspect, history | Allowed |
| Volume and network list and inspect, disk usage | Allowed |
| Ping, version, info | Allowed |
| Container logs | Allowed, `insecure_allow_read_exfiltration: true` required for the log view |
| Container process list (`top`) | Allowed with Arcane's two fixed `ps_args` values only. It returns command lines unredacted, so any other `ps_args` is refused and the environment can't be requested through it |
| Start, stop, restart, redeploy, remove, create | Denied |
| Image pull, update checks that pull, prune | Denied |
| Compose projects, volume and network create/remove, backups | Denied |
| Exec, attach, Swarm | Denied |

## Not supported

This preset is the read-only base. Arcane's management features all need Docker writes (container actions, the updater, image pulls, compose project deploys, prunes, volume browsing and backups, Swarm). Sockguard refuses those calls, so those buttons fail. Swarm mode and Podman are untested. A management variant is not shipped yet.

## Behavior notes

- Container env, mount paths and network addresses stay redacted (the sockguard defaults), so Arcane's detail pages show placeholders or empty values for them.
- Derived from Arcane v3.1.1 (`backend/internal/docker/service.go`, `backend/internal/container/`). Check the preset against the Arcane source again when you bump the pinned image.

## Usage

Set the Docker socket's group GID so sockguard can open `/var/run/docker.sock` (Linux: `stat -c '%g'`; macOS: `stat -f '%g'`), and generate Arcane's encryption key:

```bash
case "$(uname -s)" in
  Linux) export DOCKER_SOCK_GID="$(stat -c '%g' /var/run/docker.sock)" ;;
  Darwin) export DOCKER_SOCK_GID="$(stat -f '%g' /var/run/docker.sock)" ;;
  *) echo "Unsupported host OS" >&2; exit 1 ;;
esac
export ARCANE_ENCRYPTION_KEY="$(openssl rand -hex 16)"
docker compose up -d
# Arcane: http://localhost:3552
```

Keep the same `ARCANE_ENCRYPTION_KEY` across restarts, or Arcane can't read what it already encrypted.

## Hardening tips

- Add `clients.allowed_cidrs` to restrict which source IPs can reach the sockguard TCP listener within the Docker network.
- Change Arcane's default login straight away. Anyone who can open the UI can read every container's logs.
- Switch to mTLS TCP (`listen.tls`) for stronger in-network authentication if your Arcane deployment supports client certificates.
