# Sockguard + Uptime Kuma

**Who this is for:** Teams running [Uptime Kuma](https://github.com/louislam/uptime-kuma) with Docker Container monitors and wanting to eliminate the raw Docker socket mount.

**What's exposed:** Sockguard listens on plaintext TCP `:2375` on the private Docker compose network. Uptime Kuma connects to `tcp://sockguard:2375`, set as a Docker Host in the UI. The port is **not** published to the host. The Uptime Kuma UI is on port 3001.

## Why TCP instead of unix socket

Uptime Kuma can talk to a unix socket, but that means mounting a shared socket volume into both containers. TCP on the compose-internal network keeps the example simple. Uptime Kuma stores the Docker Host in its own database, so there is no environment variable to set; add it under Settings > Docker Hosts.

## Security tradeoffs

| Control | Status |
|---|---|
| sockguard: `read_only`, `cap_drop: ALL`, `no-new-privileges` | Enabled |
| No raw socket in Uptime Kuma container | Yes, TCP to sockguard only |
| Port 2375 exposed to host | No, compose-internal network only |
| Container list (`GET /containers/json`), inspect (`GET /containers/{id}/json`) | Allowed |
| Ping (`GET`/`HEAD /_ping`) | Allowed, harmless, Uptime Kuma doesn't call it |
| Version, info, events, logs, stats | Denied, Uptime Kuma doesn't call them |
| Every write, plus image, network, volume and Swarm routes | Denied |

## Supported and not supported

Supported: the Docker Container monitor (running, paused, restarting and healthcheck state) and the Docker Host "Test" button. Nothing else in Uptime Kuma uses the Docker API. Uptime Kuma has no container actions, so there is no unsupported workflow to turn on; anything else it might try is refused.

## Behavior notes

- Container env, mount paths and network addresses stay redacted (the sockguard defaults). Uptime Kuma reads only `State`, so monitors are unaffected.
- Derived from Uptime Kuma 2.5.12 (`server/model/monitor.js`, `server/docker.js`). Check the preset against the Uptime Kuma source again when you bump the pinned image. 1.x and the 3.0 betas were not checked.
- Uptime Kuma sends no `/_ping` or `/version` call. The preset allows `/_ping` like every shipped preset does and denies `/version`. That's fine for its plain HTTP requests.

## Usage

Set the Docker socket's group GID so sockguard can open `/var/run/docker.sock` (Linux: `stat -c '%g'`; macOS: `stat -f '%g'`):

```bash
case "$(uname -s)" in
  Linux) export DOCKER_SOCK_GID="$(stat -c '%g' /var/run/docker.sock)" ;;
  Darwin) export DOCKER_SOCK_GID="$(stat -f '%g' /var/run/docker.sock)" ;;
  *) echo "Unsupported host OS" >&2; exit 1 ;;
esac
docker compose up -d
# Uptime Kuma: http://localhost:3001
```

## Hardening tips

- Add `clients.allowed_cidrs` to restrict which source IPs can reach the sockguard TCP listener within the Docker network.
- Switch to mTLS TCP (`listen.tls`) for stronger in-network authentication. Uptime Kuma reads client certificates from `data/docker-tls/<host>/` (`ca.pem`, `cert.pem`, `key.pem`).
