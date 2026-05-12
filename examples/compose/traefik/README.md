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
| Tighter than bundled preset | Yes — enumerates specific paths, not broad globs |

## Usage

```bash
docker compose up -d
```

## Notes

- This config is intentionally tighter than `app/configs/traefik.yaml`, which uses broad globs and `insecure_allow_read_exfiltration: true` for compatibility. If Traefik probes an undiscovered path, add a `GET` rule for it here rather than widening to the bundled preset.
- Replace the example entrypoint/domain labels on any services you expose through Traefik.
- For Swarm mode, ensure your Swarm manager mounts the sockguard socket and the `services`/`tasks` rules above are present.
