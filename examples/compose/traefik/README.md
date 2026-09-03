# Sockguard + Traefik

**Who this is for:** Teams running Traefik as a reverse proxy and wanting to eliminate the raw Docker socket mount from the Traefik container.

**What's exposed:** A unix socket shared via a named volume. Traefik connects to `/var/run/sockguard/sockguard.sock` via its `--providers.docker.endpoint` flag. Ports 80 and 443 are the Traefik entrypoints.

## Security tradeoffs

| Control | Status |
|---|---|
| sockguard: `read_only`, `cap_drop: ALL`, `no-new-privileges` | Enabled |
| No raw socket in Traefik container | Yes — named volume unix socket |
| GET-only (no write access) | Yes |
| Raw log/archive/export streams denied | Yes — no `insecure_allow_read_exfiltration` |
| Matches bundled preset | Yes — same narrowly enumerated paths |

## Usage

Set the Docker socket's group GID so sockguard can open `/var/run/docker.sock` (Linux: `stat -c '%g'`; macOS: `stat -f '%g'`):

```bash
export DOCKER_SOCK_GID=$(stat -c '%g' /var/run/docker.sock)  # macOS: stat -f '%g'
docker compose up -d
```

## Notes

- This config's rules match `app/configs/traefik.yaml`, which was narrowed to Traefik's exact container list/inspect, network/service/task list, and node-inspect paths and no longer sets `insecure_allow_read_exfiltration: true`. If Traefik probes an undiscovered path, add a `GET` rule for it rather than widening back to a `/containers/**` glob.
- Replace the example entrypoint/domain labels on any services you expose through Traefik.
- For Swarm mode, ensure your Swarm manager mounts the sockguard socket and the `services`/`tasks` rules above are present.
