# Sockguard + Portwing

**Who this is for:** Teams running [Portwing](https://github.com/CodesWhat/portwing) as a remote Docker agent and wanting to eliminate the raw Docker socket mount from the Portwing container.

**What's exposed:** A unix socket shared via a named volume. Portwing connects to `/var/run/sockguard/sockguard.sock` instead of `/var/run/docker.sock`. Port 4000 is the Portwing API.

## Security tradeoffs

| Control | Status |
|---|---|
| sockguard: `read_only`, `cap_drop: ALL`, `no-new-privileges` | Enabled |
| Portwing: `read_only`, `cap_drop: ALL`, `no-new-privileges`, explicit non-root `user` | Enabled |
| No raw socket in Portwing container | Yes — named volume unix socket |
| Portwing API auth | Required — `TOKEN_FILE` reads a generated token from a Docker secret, not hardcoded |
| Exec denied | Yes |
| Build denied | Yes |
| Log streaming allowed; raw archive/export/attach denied | `insecure_allow_read_exfiltration: true` (required for Portwing's `GetContainerLogs()`; `/containers/*/archive`, `/export`, `/attach` stay denied) |
| Image pulls | All registries allowed (Portwing tracks arbitrary images) |
| Bind mounts on container create | Denied unless you add paths to `allowed_bind_mounts` |
| Response redaction (env, mounts, network topology) | Disabled — required for drydock passthrough topology |

## Redaction note

The Portwing preset disables `redact_mount_paths`, `redact_container_env`, and `redact_network_topology` because in the tri-tool topology (sockguard → Portwing → drydock) Portwing forwards container inspect data to drydock, which uses it to recreate containers during updates. If sockguard redacts those fields, drydock cannot reconstruct the original container spec.

If you run Portwing in standalone mode without drydock, re-enable redactions by editing `sockguard.yaml`:

```yaml
response:
  redact_mount_paths: true
  redact_container_env: true
  redact_network_topology: true
```

## Usage

Set the Docker socket's group GID so sockguard can open `/var/run/docker.sock` (Linux: `stat -c '%g'`; macOS: `stat -f '%g'`), and generate a Portwing API auth token:

```bash
export DOCKER_SOCK_GID=$(stat -c '%g' /var/run/docker.sock)  # macOS: stat -f '%g'
openssl rand -hex 32 > portwing_token.txt
sudo chown 65532:65532 portwing_token.txt && sudo chmod 0400 portwing_token.txt
docker compose up -d
# Portwing API: http://localhost:4000
```

To allowlist bind mounts for containers Portwing recreates, add host paths to `sockguard.yaml` under `request_body.container_create.allowed_bind_mounts`.

To enable exec sessions (interactive terminal access), switch to `app/configs/portwing-with-exec.yaml`.
