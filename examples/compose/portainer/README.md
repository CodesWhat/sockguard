# Sockguard + Portainer

**Who this is for:** Teams running Portainer CE for Docker management and wanting structured audit logs and body-inspection guardrails without limiting Portainer's functionality.

**What's exposed:** A unix socket shared via a named volume. Portainer connects via the `DOCKER_HOST` environment variable. Ports 9000 (HTTP) and 9443 (HTTPS) are the Portainer web UI.

## Security tradeoffs

| Control | Status |
|---|---|
| sockguard: `read_only`, `cap_drop: ALL`, `no-new-privileges` | Enabled |
| No raw socket in Portainer container | Yes — named volume unix socket |
| Structured audit log | Yes — every API call logged |
| Container create inspection | Yes — blocks privileged/host-network by default |
| Exec write guard | Disabled — `insecure_allow_body_blind_writes: true` required for Portainer exec |
| Raw log/archive streams | Enabled — `insecure_allow_read_exfiltration: true` required for Portainer log viewer |
| Near-full Docker API access | Yes — Portainer proxies the full API |

## Usage

```bash
docker compose up -d
# Portainer UI: http://localhost:9000
```

## Hardening tips

- Add `clients.allowed_cidrs` to restrict which source IPs can reach the sockguard socket.
- Remove `insecure_allow_body_blind_writes` and add `request_body.exec.allowed_commands` if your Portainer usage only runs known exec commands.
- Remove `insecure_allow_read_exfiltration` if you don't use Portainer's log viewer or container export features.
