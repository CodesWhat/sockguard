# Sockguard + remote Docker daemon (TCP+TLS, active/passive failover)

**Who this is for:** Teams running a remote Docker daemon or Swarm cluster (e.g. an HA active/standby pair) that want to proxy the Docker API over mTLS with automatic failover, without exposing the raw TCP endpoint to downstream tools.

**What's exposed:** A unix socket shared via a named volume. The downstream `docker-cli` container connects to `/var/run/sockguard/sockguard.sock` using `DOCKER_HOST`. Sockguard dials the remote daemon over TCP+TLS; downstream tools never see the remote endpoint or its credentials.

## Security tradeoffs

| Control | Status |
|---|---|
| sockguard: `read_only`, `cap_drop: ALL`, `no-new-privileges` | Enabled |
| Remote daemon credentials (certs) never reach downstream containers | Yes — certs mounted into sockguard only |
| Exec denied | Yes |
| Build denied | Yes |
| Raw log/archive streams denied | Yes — no `GET /containers/*/logs` or `/export` rules |
| mTLS to remote daemon | Yes — ca/cert/key required in `./certs/` |
| Failover to standby on health failure | Yes — `health_interval: 5s`, `health_timeout: 2s` |

## Failover semantics

The `upstream.endpoints` list is an **ordered active/passive failover set**, not a load balancer. Sockguard picks the first healthy endpoint and only promotes the next one when the active endpoint fails its health check. Both endpoints must be the same logical Docker daemon or Swarm cluster (e.g. an HA pair sharing storage). Routing the same client across two independent daemons would break container ID references, exec sessions, and owner-label isolation.

## Usage

1. Drop your TLS certificates into `./certs/`:
   - `ca.pem` — CA that signed the daemon's server cert
   - `cert.pem` — client cert (must be trusted by the daemon)
   - `key.pem` — private key for the client cert

2. Replace `dockerd-primary` and `dockerd-standby` in `sockguard.yaml` with real hostnames or IP addresses.

3. Start the stack:

```bash
docker compose up -d
```

4. Exec into the `docker-cli` container to verify connectivity:

```bash
docker compose exec docker-cli docker info
docker compose exec docker-cli docker ps
```

Sockguard logs (`format: json`) appear under the `sockguard` service. The `/health` endpoint is available inside the stack at `http://sockguard/health` for external liveness probes.
