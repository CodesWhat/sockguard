# Sockguard + GitLab Runner (Docker Executor)

**Who this is for:** Teams running self-hosted GitLab runners configured with `executor = "docker"` in `config.toml` who want to eliminate the raw Docker socket mount from the runner container and enforce a default-deny posture over the Docker API surface the runner is allowed to use.

**What's exposed:** A unix socket shared via a named volume. The runner connects to `/var/run/sockguard/sockguard.sock` instead of `/var/run/docker.sock`. No ports are exposed — the runner polls GitLab outbound, so no inbound listener is needed.

## Security tradeoffs

| Control | Status |
|---|---|
| sockguard: `read_only`, `cap_drop: ALL`, `no-new-privileges` | Enabled |
| No raw socket in runner container | Yes — named volume unix socket |
| Privileged containers denied | Yes — even if `config.toml` sets `privileged = true` |
| Host network/PID/IPC sharing denied | Yes |
| Bind mounts denied by default | Yes — populate `allowed_bind_mounts` if host paths are needed |
| Build denied | Yes |
| Image pulls | All registries allowed (CI jobs pull arbitrary images) |

## Usage

1. Register the runner (first time only). Set the Docker socket's group GID so sockguard can open `/var/run/docker.sock` (Linux: `stat -c '%g'`; macOS: `stat -f '%g'`):

   ```bash
   export DOCKER_SOCK_GID=$(stat -c '%g' /var/run/docker.sock)  # macOS: stat -f '%g'
   docker compose up -d sockguard
   docker compose run --rm gitlab-runner gitlab-runner register
   ```

   Follow the interactive prompts. When asked for the executor, enter `docker`. When asked for the default Docker image, enter any suitable base image (e.g. `alpine:latest`). The runner's `config.toml` is written to `/srv/gitlab-runner/config/` on the host.

2. Start the full stack:

   ```bash
   docker compose up -d
   ```

3. Verify the runner appears as **online** in your GitLab instance under **Settings → CI/CD → Runners**.

To allow host bind mounts for cache or build directories, add host paths to `sockguard.yaml` under `request_body.container_create.allowed_bind_mounts` and `docker compose restart sockguard`.

## Critical Notes

### `privileged = true` in `config.toml` will fail under this proxy

GitLab runner's `config.toml` supports `privileged = true` to enable Docker-in-Docker (DinD) workflows (e.g. jobs that run `docker build` inside the CI container). This preset deliberately rejects any `container_create` request body that sets `HostConfig.Privileged = true`: sockguard returns `403` before dockerd ever acts on the request. Any job that relies on a privileged container — whether via `privileged = true` in the runner config or via a `.gitlab-ci.yml` `services:` entry that needs elevated access — will fail with a 403 at container creation time.

**Workaround A — rootless DinD via sysbox:** Remove `privileged = true` from `config.toml` and configure your CI jobs to use [sysbox](https://github.com/nestybox/sysbox) as the container runtime. Sysbox provides strong host isolation without requiring the host's Linux security boundaries to be dropped.

**Workaround B — dedicated privileged runner:** Move projects that genuinely require privileged containers to a separate runner that mounts `/var/run/docker.sock` directly and is scoped to only those projects via runner tags. Keep the sockguard-fronted runner for all other pipelines. The trade-off is intentional — privileged containers bypass virtually every Linux security boundary and are incompatible with a meaningful host-isolation posture.
