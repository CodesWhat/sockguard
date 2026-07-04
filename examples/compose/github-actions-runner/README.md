# Sockguard + GitHub Actions Self-Hosted Runner

**Who this is for:** Teams running a self-hosted GitHub Actions runner with Docker support and wanting to eliminate the raw Docker socket mount from the runner container.

**What's exposed:** A unix socket shared via a named volume. The runner connects to `/var/run/sockguard/sockguard.sock` (via `DOCKER_HOST`) instead of `/var/run/docker.sock`. No ports are needed — the runner phones home to GitHub over HTTPS.

## Security tradeoffs

| Control | Status |
|---|---|
| sockguard: `read_only`, `cap_drop: ALL`, `no-new-privileges` | Enabled |
| No raw socket in runner container | Yes — named volume unix socket |
| Privileged containers denied | Yes (even if a workflow requests `options: --privileged`) |
| Host network / PID / IPC sharing denied | Yes |
| Bind mounts denied by default | Yes — add paths to `allowed_bind_mounts` if needed |
| Build denied | Yes — workflows using `docker/build-push-action` will fail until widened |
| Image pulls | All registries allowed (GHCR, Docker Hub, ECR, GAR, etc.) |

## Usage

Copy the example env file and fill in your runner registration details:

```bash
cp .env.example .env
# Edit .env — set REPO_URL, RUNNER_NAME, RUNNER_TOKEN, LABELS, RUNNER_WORKDIR
export DOCKER_SOCK_GID=$(stat -c '%g' /var/run/docker.sock)  # macOS: stat -f '%g'
docker compose up -d
```

Required `.env` variables:

| Variable | Description |
|---|---|
| `REPO_URL` | Full URL of the repository or organisation to register the runner against (e.g. `https://github.com/myorg/myrepo`) |
| `RUNNER_NAME` | Unique name for this runner instance |
| `RUNNER_TOKEN` | Registration token from Settings → Actions → Runners → New self-hosted runner |
| `LABELS` | Comma-separated runner labels (e.g. `self-hosted,linux,docker`) |
| `RUNNER_WORKDIR` | Working directory inside the runner container (e.g. `/tmp/runner`) |

## Notes

**DinD-style workflows will fail by design.** Any workflow step or job that requests `privileged: true` (Docker-in-Docker, Buildah, Kaniko in privileged mode) will be denied by sockguard at container-create time. This is intentional — if a compromised workflow can spawn a privileged container it can escape to the host. Redesign those workflows to use rootless builds or a separate runner label that targets a dedicated builder host.

**`docker build` / `docker buildx` are denied by default.** The `POST /build` endpoint is not in the allowlist. Workflows that invoke `docker/build-push-action` or `docker build` directly will fail with a 403 until you add `{ method: POST, path: "/build" }` to `sockguard.yaml` and accept the expanded attack surface.

**Runner authentication is out of scope.** This preset controls *what* the runner process can do once it reaches the proxy, but does not authenticate *which* process on the host connects to the socket. See the "Security note — authentication" section in the bundled preset (`app/configs/github-actions-runner.yaml`) for guidance on pairing this with peer-credential or CIDR controls.
