# Sockguard + drydock

**Who this is for:** Teams running [drydock](https://github.com/CodesWhat/drydock) for container update management and wanting to eliminate the raw Docker socket mount from the drydock container.

**What's exposed:** A unix socket shared via a named volume. Drydock connects to `/var/run/sockguard/sockguard.sock` instead of `/var/run/docker.sock`. Port 3000 is the drydock web UI.

## Security tradeoffs

| Control | Status |
|---|---|
| sockguard: `read_only`, `cap_drop: ALL`, `no-new-privileges` | Enabled |
| No raw socket in drydock container | Yes — named volume unix socket |
| Exec denied | Yes |
| Build denied | Yes |
| Raw log/archive streams denied | Yes — no `insecure_allow_read_exfiltration` |
| Image pulls | All registries allowed (drydock tracks arbitrary images) |
| Bind mounts on container create | Denied unless you add paths to `allowed_bind_mounts` |

## Usage

```bash
docker compose up -d
# drydock UI: http://localhost:3000
```

To allowlist bind mounts for containers drydock recreates, add host paths to `sockguard.yaml` under `request_body.container_create.allowed_bind_mounts`.
