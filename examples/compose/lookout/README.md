# Sockguard + lookout

**Who this is for:** Teams running [lookout](https://github.com/CodesWhat/lookout) as a remote Docker agent and wanting to eliminate the raw Docker socket mount from the lookout container.

**What's exposed:** A unix socket shared via a named volume. Lookout connects to `/var/run/sockguard/sockguard.sock` instead of `/var/run/docker.sock`. Port 4000 is the lookout API.

## Security tradeoffs

| Control | Status |
|---|---|
| sockguard: `read_only`, `cap_drop: ALL`, `no-new-privileges` | Enabled |
| No raw socket in lookout container | Yes — named volume unix socket |
| Exec denied | Yes |
| Build denied | Yes |
| Log streaming allowed; raw archive/export/attach denied | `insecure_allow_read_exfiltration: true` (required for lookout's `GetContainerLogs()`; `/containers/*/archive`, `/export`, `/attach` stay denied) |
| Image pulls | All registries allowed (lookout tracks arbitrary images) |
| Bind mounts on container create | Denied unless you add paths to `allowed_bind_mounts` |
| Response redaction (env, mounts, network topology) | Disabled — required for drydock passthrough topology |

## Redaction note

The lookout preset disables `redact_mount_paths`, `redact_container_env`, and `redact_network_topology` because in the tri-tool topology (sockguard → lookout → drydock) lookout forwards container inspect data to drydock, which uses it to recreate containers during updates. If sockguard redacts those fields, drydock cannot reconstruct the original container spec.

If you run lookout in standalone mode without drydock, re-enable redactions by editing `sockguard.yaml`:

```yaml
response:
  redact_mount_paths: true
  redact_container_env: true
  redact_network_topology: true
```

## Usage

```bash
docker compose up -d
# lookout API: http://localhost:4000
```

To allowlist bind mounts for containers lookout recreates, add host paths to `sockguard.yaml` under `request_body.container_create.allowed_bind_mounts`.

To enable exec sessions (interactive terminal access), switch to `app/configs/lookout-with-exec.yaml`.
