# Sockguard + CIS Docker Benchmark Gate

**Who this is for:** Teams that need to evidence CIS Docker Benchmark v1.6.0 Section 5 (Container Runtime) compliance and want a single chokepoint where every `docker run` is checked before dockerd executes it. Any non-compliant create request returns `403` at the proxy layer — no container is ever started. The gate is consumer-agnostic: Portainer, a CI runner, a custom orchestrator, or a human with the Docker CLI all go through the same enforcement path.

**What's exposed:** A unix socket shared via a named Docker volume (`sockguard-socket`). The placeholder `your-app` service uses the official `docker:cli` image so you can exec into it and run `docker run` commands against the gated socket to verify the gate interactively. Replace `your-app` with your real downstream consumer, pointing it at `unix:///var/run/sockguard/sockguard.sock` via `DOCKER_HOST`.

## Security tradeoffs

| Control | Status |
|---|---|
| sockguard: `read_only`, `cap_drop: ALL`, `no-new-privileges` | Enabled |
| CIS 5.4 — no privileged containers | Enforced |
| CIS 5.9–5.11 — no host net/PID/IPC | Enforced |
| CIS 5.15–5.17 — kernel capability allowlist + drop ALL | Enforced |
| CIS 5.22 — no `docker exec --privileged` | Enforced |
| CIS 5.25 — no-new-privileges required | Enforced |
| CIS 5.30 — read-only root FS required | Enforced |
| Bind mounts denied by default | Yes — add paths to `allowed_bind_mounts` when the workload requires |

## Usage

Set the Docker socket's group GID so sockguard can open `/var/run/docker.sock` (Linux: `stat -c '%g'`; macOS: `stat -f '%g'`):

```bash
export DOCKER_SOCK_GID=$(stat -c '%g' /var/run/docker.sock)  # macOS: stat -f '%g'
docker compose up -d
```

## Verification

### Start the stack

```bash
docker compose up -d
docker compose exec your-app docker ps   # confirms the socket is reachable
```

### Blocked request (should return 403)

```bash
docker compose exec your-app \
  docker run --privileged --rm alpine ls
```

sockguard rejects this before dockerd sees it. You will see a structured denial log line from sockguard and a `docker: Error response from daemon: ...` on the client side.

### Allowed request (should succeed)

```bash
docker compose exec your-app \
  docker run \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --memory 64m \
    --cpus 0.5 \
    --pids-limit 64 \
    --rm alpine ls /
```

This satisfies every inspectable CIS Section 5 control the preset enforces and passes through to dockerd.

### Curl variants (from the host)

If you prefer to hit the socket directly from the host rather than via `exec`:

```bash
# Allowed — basic container list
curl --unix-socket /var/run/sockguard/sockguard.sock \
  http://localhost/containers/json

# Blocked — exec endpoint (denied by rule)
curl --unix-socket /var/run/sockguard/sockguard.sock \
  -X POST http://localhost/containers/my-container/exec
```

The named volume socket path on the host is typically visible under the Docker volume mount; use `docker inspect` on the sockguard container to find the exact host path if needed.

## Customizing the gate

Any deviation from the preset — loosening a control because a workload genuinely requires it — should be a **single-line diff** against `sockguard.yaml`. That diff is your audit trail: reviewers can see exactly which CIS control was relaxed, which value it was changed to, and when (via `git log`).

Examples of compliant deviations:

```yaml
# Allow one specific bind mount for a log aggregator
allowed_bind_mounts:
  - /var/log/app:/app/logs:ro

# Allow NET_BIND_SERVICE for a workload serving on port 80
allowed_capabilities:
  - NET_BIND_SERVICE

# Allow image trust enforcement for signed images only (CIS 4.5)
image_trust:
  mode: enforce
  allowed_keyless:
    - issuer: https://token.actions.githubusercontent.com
      subject_prefix: https://github.com/your-org/
```

Do **not** flip `allow_privileged`, `allow_host_network`, `allow_host_pid`, or `allow_host_ipc` to `true` without a change-management review — those undo the core Section 5 controls this preset is designed to evidence.

## Beyond Section 5

The full CIS Docker Benchmark covers daemon configuration (Section 2), Docker files (Section 4), image hygiene, and swarm security — areas that sockguard cannot enforce at the API boundary. See the docs page for the complete control mapping, companion checks for non-inspectable controls, and guidance on combining this preset with image-trust enforcement:

[docs/content/docs/cis-docker-benchmark.mdx](../../../docs/content/docs/cis-docker-benchmark.mdx)

Or on the live site: [getsockguard.com/docs/cis-docker-benchmark](https://getsockguard.com/docs/cis-docker-benchmark)
