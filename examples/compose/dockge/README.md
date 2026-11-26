# Sockguard + Dockge

**Who this is for:** Teams running [Dockge](https://github.com/louislam/dockge) to manage Compose stacks who want to drop the raw Docker socket mount and bound what a stack deploy can do.

**What's exposed:** Sockguard listens on plaintext TCP `:2375` on the private Docker compose network. Dockge's `docker` CLI and Compose plugin connect via `DOCKER_HOST=tcp://sockguard:2375`. The port is **not** published to the host. The Dockge UI is on port 5001.

## Why TCP instead of unix socket

Dockge runs the `docker` CLI as a child process and passes `DOCKER_HOST` through, so the proxy has to be reachable over TCP on the compose-internal network.

## Security tradeoffs

Dockge deploys stacks, so this preset has to allow container, network and volume creation. It bounds that rather than removing it.

| Control | Status |
|---|---|
| sockguard: `read_only`, `cap_drop: ALL`, `no-new-privileges` | Enabled |
| No raw socket in Dockge container | Yes, TCP to sockguard only |
| Port 2375 exposed to host | No, compose-internal network only |
| Owner-label isolation (`ownership.owner: dockge`) | Enabled, Dockge sees and touches only what it created |
| Privileged containers, host network/PID/IPC/user namespaces, extra capabilities, devices | Denied by container-create inspection |
| Bind mounts | Only under `/opt/stacks` |
| Custom network and volume drivers | Denied |
| Image pull | Any registry |
| Container logs | Allowed, `insecure_allow_read_exfiltration: true` required |
| Exec, attach, build, image remove, volume remove | Denied |

**Residual risk:** anyone who can edit a stack's `compose.yaml` in Dockge can run any image with any command, as root, with network access and the stacks directory mounted. The UI login is the trust boundary. Keep it behind real authentication.

## Not supported

Sockguard refuses these, so the matching Dockge actions fail:

- The stack shell and the Dockge console (`docker compose exec`, attach).
- `docker compose build` and `up --build`.
- `down --rmi` and `down -v`.
- Inline `configs:` and `secrets:` with `content:` (Compose copies them in with `PUT /containers/*/archive`).
- Compose `post_start` and `pre_stop` hooks (they use exec).

## Behavior notes

- Stacks that already run (created without the proxy) don't show up and can't be adopted. Run `docker compose down` on them, then deploy them from Dockge.
- `external: true` networks and volumes must have been created through this proxy, or Compose treats them as foreign and fails.
- Dockge's network picker lists only networks it owns.
- Engine versions: the allowed calls were derived from Docker Compose v5.8.0 and Dockge 1.5.0. The preset is not tested against Podman.
- Dockge pulls images with whatever registry credentials its own `~/.docker/config.json` holds. Sockguard forwards the pull request unchanged.
- Check the preset against the Dockge and Compose source again when you bump the pinned image.

## Usage

Set the Docker socket's group GID so sockguard can open `/var/run/docker.sock` (Linux: `stat -c '%g'`; macOS: `stat -f '%g'`):

```bash
case "$(uname -s)" in
  Linux) export DOCKER_SOCK_GID="$(stat -c '%g' /var/run/docker.sock)" ;;
  Darwin) export DOCKER_SOCK_GID="$(stat -f '%g' /var/run/docker.sock)" ;;
  *) echo "Unsupported host OS" >&2; exit 1 ;;
esac
docker compose up -d
# Dockge: http://localhost:5001
```

If your stacks live somewhere other than `/opt/stacks`, change `DOCKGE_STACKS_DIR`, the stacks volume, and `allowed_bind_mounts` in `sockguard.yaml` together.

## Hardening tips

- Add `clients.allowed_cidrs` to restrict which source IPs can reach the sockguard TCP listener within the Docker network.
- Narrow `allowed_bind_mounts` to specific stack subdirectories, and set `image_pull.allow_all_registries: false` with an `allowed_registries` list if your stacks pull from known registries only.
- Switch to mTLS TCP (`listen.tls`) for stronger in-network authentication if your setup supports client certificates.
