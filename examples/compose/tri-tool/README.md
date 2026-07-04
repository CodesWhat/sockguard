# Sockguard + Portwing + drydock

**Who this is for:** Teams running the full tri-tool topology — [Portwing](https://github.com/CodesWhat/portwing) as a remote Docker agent reporting into [drydock](https://github.com/CodesWhat/drydock) — and wanting to eliminate the raw Docker socket mount from both the Portwing and drydock containers.

**What's exposed:** A unix socket shared via a named volume. Portwing connects to `/var/run/sockguard/sockguard.sock` instead of `/var/run/docker.sock`. drydock never sees a Docker socket at all — it connects to Portwing over HTTP in **Standard Mode** (drydock is the controller, Portwing is the agent) and gets every container/image fact secondhand, already filtered by sockguard. Port 4000 is the Portwing API; port 3000 is the drydock web UI.

This bundle defaults to **no exec** (the plain `portwing` preset, not `portwing-with-exec`) and to Standard Mode (not Portwing's experimental Edge Mode WebSocket dial-out — see drydock's `DD_EXPERIMENTAL_PORTWING` docs if you need that instead).

## Security tradeoffs

| Control | Status |
|---|---|
| sockguard: `read_only`, `cap_drop: ALL`, `no-new-privileges` | Enabled |
| Portwing: `read_only`, `cap_drop: ALL`, `no-new-privileges`, explicit non-root `user` | Enabled |
| drydock: hardened rootfs/user | Not applied — drydock's entrypoint provisions `/store` as root, then drops privileges itself via `su-exec`; matches this repo's existing `examples/compose/drydock/` |
| No raw socket in Portwing container | Yes — named volume unix socket |
| No Docker socket in drydock container at all | Yes — drydock only ever talks to Portwing's HTTP API |
| Portwing<->drydock shared secret | Required — a generated token, mounted as a Docker secret into both containers (`TOKEN_FILE` / `DD_AGENT_PORTWING_SECRET__FILE`), never in plaintext env |
| Exec denied | Yes |
| Build denied | Yes |
| Log streaming allowed; raw archive/export/attach denied | `insecure_allow_read_exfiltration: true` (required for Portwing's `GetContainerLogs()`; `/containers/*/archive`, `/export`, `/attach` stay denied) |
| Image pulls | All registries allowed (Portwing tracks arbitrary images) |
| Bind mounts on container create | Denied unless you add paths to `allowed_bind_mounts` |
| Response redaction (env, mounts, network topology) | Disabled — required for drydock passthrough topology |
| Portwing<->drydock transport | Plain HTTP over the compose network (`DD_AGENT_ALLOW_INSECURE_SECRET=true`); use TLS for any cross-host deployment |

## Redaction note

The Portwing preset disables `redact_mount_paths`, `redact_container_env`, and `redact_network_topology` because in this tri-tool topology (sockguard → Portwing → drydock) Portwing forwards container inspect data to drydock, which uses it to recreate containers during updates. If sockguard redacts those fields, drydock cannot reconstruct the original container spec.

If you run Portwing without drydock, re-enable redactions by editing `sockguard.yaml`:

```yaml
response:
  redact_mount_paths: true
  redact_container_env: true
  redact_network_topology: true
```

## Known limitation: no remote updates yet

Portwing's Standard Mode agent doesn't implement the update-trigger endpoints yet — `POST /api/triggers/{type}/{name}` (and `.../batch`) both return `501`. drydock will discover Portwing, list its containers, and stream live container add/update/remove events, but it cannot push an update *to* Portwing through this connection. Use Portwing's own REST API for updates until that lands.

## Usage

Set the Docker socket's group GID so sockguard can open `/var/run/docker.sock` (Linux: `stat -c '%g'`; macOS: `stat -f '%g'`), and generate the shared Portwing<->drydock secret:

```bash
export DOCKER_SOCK_GID=$(stat -c '%g' /var/run/docker.sock)  # macOS: stat -f '%g'
openssl rand -hex 32 > portwing_token.txt
sudo chown 65532:65532 portwing_token.txt && sudo chmod 0400 portwing_token.txt
docker compose up -d
# Portwing API: http://localhost:4000
# drydock UI:   http://localhost:3000
```

drydock should log `Handshake successful. Received N containers.` for the `portwing` agent once it connects. If it doesn't, check `docker compose logs drydock` — a `401` means the secret file didn't match on both sides; `ECONNREFUSED` means Portwing isn't up yet.

To allowlist bind mounts for containers Portwing recreates, add host paths to `sockguard.yaml` under `request_body.container_create.allowed_bind_mounts`.

To enable exec sessions (interactive terminal access) through Portwing, switch `sockguard.yaml` here to the [`app/configs/portwing-with-exec.yaml`](../../../app/configs/portwing-with-exec.yaml) preset — see the main README's [bundled presets](../../../README.md#bundled-presets-15) list for the full set.
