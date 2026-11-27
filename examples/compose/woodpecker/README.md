# Sockguard + Woodpecker CI (docker backend)

**Who this is for:** Teams running a Woodpecker agent with `WOODPECKER_BACKEND=docker` who want to take the raw Docker socket out of the agent container and bound what pipelines can ask the daemon to do.

**What's exposed:** A unix socket shared through a named volume. The agent connects to `/var/run/sockguard/sockguard.sock` through `WOODPECKER_BACKEND_DOCKER_HOST`. No ports are published. The agent dials out to the Woodpecker server, so nothing listens inbound.

Derived from Woodpecker v3.21.0 (`pipeline/backend/docker/docker.go` and `convert.go`).

## Security tradeoffs

| Control | Status |
|---|---|
| sockguard: `read_only`, `cap_drop: ALL`, `no-new-privileges` | Enabled |
| No raw socket in the agent container | Yes, named volume unix socket |
| Privileged steps denied | Yes, including admin-trusted plugins that set `privileged` |
| Host network/PID/IPC sharing, devices, added capabilities, sysctls, published ports | Denied |
| Host bind mounts | Denied; add narrow entries to `allowed_bind_mounts` if a trusted repo needs them |
| Owner-label isolation | `ownership.owner: woodpecker` stamps and scopes containers, networks and volumes |
| Exec, attach, stats, events, build, image list/inspect, volume and network reads | Denied, the backend never calls them |
| Image pulls | All registries allowed (pipelines name arbitrary images) |

## Usage

1. Set the Docker socket's group GID so sockguard can open `/var/run/docker.sock` (Linux: `stat -c '%g'`; macOS: `stat -f '%g'`), plus your server address and agent secret:

   ```bash
   case "$(uname -s)" in
     Linux) docker_sock_gid="$(stat -c '%g' /var/run/docker.sock)" ;;
     Darwin) docker_sock_gid="$(stat -f '%g' /var/run/docker.sock)" ;;
     *) echo "Unsupported host OS" >&2; exit 1 ;;
   esac
   {
     printf 'DOCKER_SOCK_GID=%s\n' "$docker_sock_gid"
     printf 'WOODPECKER_SERVER=%s\n' "woodpecker.example.com:9000"
     printf 'WOODPECKER_AGENT_SECRET=%s\n' "replace-with-your-agent-secret"
   } > .env
   ```

2. Start the stack:

   ```bash
   docker compose up -d
   ```

3. Confirm the agent shows up under **Admin, Agents** in the Woodpecker UI and run a pipeline.

## What does not work

- **Privileged steps.** Docker-in-Docker and buildx plugins that need `privileged: true` fail with a 403 at container create. Run those on a separate agent with its own, deliberately broader policy.
- **Host volumes.** A trusted repo's `volumes:` host paths and `WOODPECKER_BACKEND_DOCKER_VOLUMES` are refused until you allowlist them.
- **`WOODPECKER_BACKEND_DOCKER_NETWORK`.** Joining a pre-existing network is refused because the agent does not own it.
- **`extra_hosts`.** sockguard refuses `HostConfig.ExtraHosts` on every container create.
- **Devices, extra capabilities, sysctls, published ports.** Refused.
- **Other backends and engines.** Kubernetes and local backends do not use the Docker socket. Windows engines and Podman are untested.

## Residual risk

Steps still run arbitrary images and commands from every pipeline the agent accepts, as root unless a step sets `user`, with outbound network access. sockguard keeps those containers from reaching the host or each other's owners, it does not make untrusted pipelines safe. Only the agent should be able to reach the sockguard socket.
