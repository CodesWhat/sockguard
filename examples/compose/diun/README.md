# Sockguard + Diun

**Who this is for:** Teams running [Diun](https://crazymax.dev/diun/) to get notified of new image versions and wanting its Docker provider to read through a read-only proxy instead of the raw Docker socket.

**What's exposed:** A unix socket shared via a named volume. Diun connects via `DIUN_PROVIDERS_DOCKER_ENDPOINT`. Nothing is published to the host.

## Security tradeoffs

| Control | Status |
|---|---|
| sockguard: `read_only`, `cap_drop: ALL`, `no-new-privileges` | Enabled |
| No raw socket in Diun container | Yes — named volume unix socket |
| Writes | None — every non-GET/HEAD is denied |
| Allowed calls | `/_ping`, `/version`, `GET /containers/json`, image inspect |
| Container inspect, image list, logs, archive | Denied |
| Network topology redaction | Off in this preset. Since v3.0 turning it on no longer breaks Diun's decoding (addresses read as type-valid empty values; `NetworkMode` and network IDs are not redacted), so you can enable it if you don't need container addresses |
| Mount path and container env redaction | On (default) |

## Usage

Set the Docker socket's group GID so sockguard can open `/var/run/docker.sock` (Linux: `stat -c '%g'`; macOS: `stat -f '%g'`):

```bash
case "$(uname -s)" in
  Linux) export DOCKER_SOCK_GID="$(stat -c '%g' /var/run/docker.sock)" ;;
  Darwin) export DOCKER_SOCK_GID="$(stat -f '%g' /var/run/docker.sock)" ;;
  *) echo "Unsupported host OS" >&2; exit 1 ;;
esac
docker compose up -d
docker compose logs -f diun
```

Diun only watches containers labelled `diun.enable=true` (`DIUN_PROVIDERS_DOCKER_WATCHBYDEFAULT=false`). Add a `DIUN_NOTIF_*` block for your notification channel; none is configured here, so Diun logs `No notifier available`.

## Hardening tips

- Swarm users need `GET /services` for Diun's Swarm provider; it is not in the preset.
- Use client CIDR gates or mTLS client-certificate profiles if other consumers share the sockguard socket volume.
