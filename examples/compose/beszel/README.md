# Sockguard + Beszel agent

**Who this is for:** Teams running the [Beszel](https://beszel.dev) agent for container monitoring (list, CPU, memory, network, health, image update checks) and wanting to eliminate the raw Docker socket mount.

**What's exposed:** Sockguard writes a filtered unix socket into a shared named volume. The agent reads it through `DOCKER_HOST=unix:///var/run/sockguard/sockguard.sock`. Nothing listens on TCP.

## Security tradeoffs

| Control | Status |
|---|---|
| sockguard: `read_only`, `cap_drop: ALL`, `no-new-privileges` | Enabled |
| No raw socket in the agent container | Yes, filtered socket only |
| Container list, inspect, stats | Allowed |
| Ping, version, info | Allowed |
| Image inspect (update checks) | Allowed |
| Container logs (hub log view) | Denied |
| Create, start, stop, exec, attach, image, network, volume writes | Denied |

## Not supported

The hub's container log view calls `GET /containers/{id}/logs`, which sockguard refuses in this preset because logs are a read-exfiltration route. Opening a container's logs in the hub shows an error. To enable it, add `GET /containers/*/logs` as an allow rule above the final deny and set `insecure_allow_read_exfiltration: true`. Podman and Swarm are untested.

## Behavior notes

- The agent strips `Config.Env` from inspect responses before sending them to the hub, and sockguard redacts container env too.
- Image update checks inspect the local image and then query the registry directly from the agent. Set `DOCKER_IMAGE_CHECK=false` on the agent and drop the `/images/**/json` rule if you don't use them.
- Beszel needs Docker 25.0.0 or newer for one-shot stats, and sends no API version prefix.
- Derived from Beszel v0.21.2 (`agent/docker.go`, `agent/docker_registry.go`). Check the preset against the agent source again when you bump the pinned image.

## Usage

Set the Docker socket's group GID so sockguard can open `/var/run/docker.sock` (Linux: `stat -c '%g'`; macOS: `stat -f '%g'`), and the three values from the hub's "Add system" dialog:

```bash
case "$(uname -s)" in
  Linux) export DOCKER_SOCK_GID="$(stat -c '%g' /var/run/docker.sock)" ;;
  Darwin) export DOCKER_SOCK_GID="$(stat -f '%g' /var/run/docker.sock)" ;;
  *) echo "Unsupported host OS" >&2; exit 1 ;;
esac
export BESZEL_KEY="<hub public key>"
export BESZEL_HUB_URL="<hub url>"
export BESZEL_AGENT_TOKEN="<agent auth value>"
docker compose up -d
```
