# Sockguard + Homepage

**Who this is for:** Teams running [Homepage](https://gethomepage.dev) with Docker label discovery and container status/stats widgets, and wanting to drop the raw Docker socket mount from the dashboard container.

**What's exposed:** A unix socket shared via a named volume. Homepage reads it through the `socket:` entry in `docker.yaml` (server name `sockguard`, referenced by the `homepage.server` label). The dashboard is on port 3000.

## Security tradeoffs

| Control | Status |
|---|---|
| sockguard: `read_only`, `cap_drop: ALL`, `no-new-privileges` | Enabled |
| No raw socket in Homepage container | Yes — named volume unix socket |
| Writes | None — every non-GET is denied |
| Container list, inspect, stats | Allowed |
| Swarm service/task reads | Allowed (`/services`, `/services/*`, `/tasks`) |
| Logs, archive, export, attach | Denied — no read-exfiltration acknowledgment needed |

## Usage

Set the Docker socket's group GID so sockguard can open `/var/run/docker.sock` (Linux: `stat -c '%g'`; macOS: `stat -f '%g'`):

```bash
case "$(uname -s)" in
  Linux) export DOCKER_SOCK_GID="$(stat -c '%g' /var/run/docker.sock)" ;;
  Darwin) export DOCKER_SOCK_GID="$(stat -f '%g' /var/run/docker.sock)" ;;
  *) echo "Unsupported host OS" >&2; exit 1 ;;
esac
docker compose up -d
# Homepage: http://localhost:3000
```

Edit `HOMEPAGE_ALLOWED_HOSTS` in `docker-compose.yml` if you reach the dashboard under another hostname. Add `homepage.*` labels to the containers you want listed.

## Hardening tips

- Do not publish port 3000 beyond a trusted network, or put it behind an authenticating reverse proxy. Homepage has no login of its own.
- Use client CIDR gates or mTLS client-certificate profiles if other consumers share the sockguard socket volume.
