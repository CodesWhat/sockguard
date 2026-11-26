# Sockguard + Komodo Periphery

**Who this is for:** Teams running [Komodo](https://komo.do) who want Periphery to monitor a host (containers, images, networks, volumes, stats, logs) without mounting the raw Docker socket.

**What's exposed:** Sockguard listens on plaintext TCP `:2375` on the private Docker compose network. Periphery connects via `DOCKER_HOST=tcp://sockguard:2375`. The port is **not** published to the host.

## Why TCP instead of unix socket

Periphery's Docker client and the `docker` CLI it shells out to both read `DOCKER_HOST`, and the proxy has to be reachable over TCP on the compose-internal network.

## Security tradeoffs

| Control | Status |
|---|---|
| sockguard: `read_only`, `cap_drop: ALL`, `no-new-privileges` | Enabled |
| No raw socket in Periphery container | Yes, TCP to sockguard only |
| Port 2375 exposed to host | No, compose-internal network only |
| Container list, inspect, stats | Allowed |
| Container logs | Allowed, `insecure_allow_read_exfiltration: true` required for log views |
| Image list, inspect, history | Allowed |
| Network and volume list, inspect | Allowed |
| Ping, version | Allowed |
| Deploy, stack and build actions, container start/stop/restart/pause/remove/rename | Denied |
| Exec, attach (Periphery terminals) | Denied |
| Image pull and remove, prune, Swarm, disk usage, events | Denied |

## Not supported

Periphery's write features are not supported by this preset. Container create, start, stop, restart, pause, remove and rename, image pull and remove, networks and volumes create and remove, all prune actions, Komodo Stacks (`docker compose`), Builds, Swarm mode, and terminals and container exec all fail with a deny from sockguard. Turning them on in Komodo gives you buttons that fail. A deploy-capable Periphery needs broad writes (container create with a caller-defined config, compose, image builds), so this example does not bound them. Use Komodo Core for monitoring here, and deploy through a different path.

## Behavior notes

- Container env, mount paths and network addresses stay redacted (the sockguard defaults), so Komodo's container details show placeholders or empty values for them.
- Komodo stats use `docker stats --no-stream`, which calls `GET /containers/json` then `GET /containers/{id}/stats`. Both are allowed.
- Derived from Komodo v2.3.4 (`bin/periphery/src`). Check the preset against the Komodo source again when you bump the pinned image.
- Set `PERIPHERY_DISABLE_TERMINALS` and `PERIPHERY_DISABLE_CONTAINER_EXEC` to `true`, as the compose file does.

## Usage

Set the Docker socket's group GID so sockguard can open `/var/run/docker.sock` (Linux: `stat -c '%g'`; macOS: `stat -f '%g'`), and fill in the Core address, server name and key settings in the compose file:

```bash
case "$(uname -s)" in
  Linux) export DOCKER_SOCK_GID="$(stat -c '%g' /var/run/docker.sock)" ;;
  Darwin) export DOCKER_SOCK_GID="$(stat -f '%g' /var/run/docker.sock)" ;;
  *) echo "Unsupported host OS" >&2; exit 1 ;;
esac
docker compose up -d
```

## Hardening tips

- Add `clients.allowed_cidrs` to restrict which source IPs can reach the sockguard TCP listener within the Docker network.
- Anyone who controls Komodo Core can read every container's logs through Periphery. Protect Core accordingly.
- Switch to mTLS TCP (`listen.tls`) for stronger in-network authentication if your setup supports client certificates.
