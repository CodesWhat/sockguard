# Sockguard + Autoheal

**Who this is for:** Teams running [docker-autoheal](https://github.com/willfarrell/docker-autoheal) to restart containers that fail their healthcheck, and wanting the restarter to hold nothing more than the right to restart.

**What's exposed:** A unix socket shared via a named volume. Autoheal connects via `DOCKER_SOCK=/var/run/sockguard/sockguard.sock`. Nothing is published to the host. The `web` service is a demo target with a healthcheck and the `autoheal=true` label.

## Security tradeoffs

| Control | Status |
|---|---|
| sockguard: `read_only`, `cap_drop: ALL`, `no-new-privileges` | Enabled |
| No raw socket in Autoheal container | Yes — named volume unix socket |
| Container list and inspect | Allowed |
| Container restart | Allowed — the only write |
| Create, exec, start, stop, delete, image and network calls | Denied |

## Usage

Set the Docker socket's group GID so sockguard can open `/var/run/docker.sock` (Linux: `stat -c '%g'`; macOS: `stat -f '%g'`):

```bash
case "$(uname -s)" in
  Linux) export DOCKER_SOCK_GID="$(stat -c '%g' /var/run/docker.sock)" ;;
  Darwin) export DOCKER_SOCK_GID="$(stat -f '%g' /var/run/docker.sock)" ;;
  *) echo "Unsupported host OS" >&2; exit 1 ;;
esac
docker compose up -d
docker compose logs -f autoheal
```

To see it work, break the demo container's healthcheck (`docker compose exec web rm /usr/share/nginx/html/index.html`) and watch Autoheal restart it.

## Hardening tips

- Autoheal restarts any container labelled `autoheal=true`. Keep that label to the services you actually want healed.
- Use client CIDR gates or mTLS client-certificate profiles if other consumers share the sockguard socket volume.
