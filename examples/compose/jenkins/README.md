# Sockguard + Jenkins (Docker plugin)

**Who this is for:** Teams running Jenkins with the [Docker plugin](https://plugins.jenkins.io/docker-plugin/) to provision agent containers on demand, and wanting to stop handing Jenkins the raw Docker socket.

**What's exposed:** Sockguard listens on plaintext TCP `:2375` on the private Docker compose network. In Jenkins, add a Docker cloud with Docker Host URI `tcp://sockguard:2375`. The port is **not** published to the host. The Jenkins UI is on port 8080.

## Setup

Install the Docker plugin, then add a Docker cloud pointed at `tcp://sockguard:2375`. Add an agent template with the **Inbound** connector and set its Docker Image to the exact reference in `allowed_images`. The default is `docker.io/jenkins/inbound-agent:3396.ve02b_5cde31b_2-5-jdk21`. Jenkins must be reachable from the agent container by the URL set in Jenkins' location settings (or the connector's Jenkins URL override).

Replace the `allowed_images` entry with your own agent images. The match is exact and fully qualified, so a template that says `jenkins/inbound-agent` fails the create.

## Security tradeoffs

| Control | Status |
|---|---|
| sockguard: `read_only`, `cap_drop: ALL`, `no-new-privileges` | Enabled |
| No raw socket in the Jenkins container | Yes, TCP to sockguard only |
| Port 2375 exposed to host | No, compose-internal network only |
| Container create | Allowed for `allowed_images` only, body-inspected |
| Privileged, host namespaces, bind mounts, devices, capability additions, sysctls, published ports | Denied on create |
| Image pull | `docker.io` only |
| Stop, remove (force and anonymous volumes included) | Allowed, limited to containers this proxy created (`ownership.owner`) |
| Exec, attach, archive copy, logs, top | Denied |
| Networks, volumes, build, swarm | Denied |

## Supported and not supported

Supported: the Docker plugin with the Inbound (JNLP) connector. This is the workflow that fits least privilege, because the agent container dials back to Jenkins and Sockguard never sees a shell session.

Not supported, and refused by the proxy:

- The Attach connector (needs exec and file copy into the container).
- The SSH connector (needs file copy and published ports).
- The container log read the plugin does on agent disconnect. The plugin ignores the failure.
- Template options that mount host paths, use `--volumes-from`, add capabilities, run privileged, join the host network, or add devices.
- docker-workflow's `docker.image().inside()` and `docker.build()`. They run the `docker` CLI against the same socket with host bind mounts, `--volumes-from`, exec and top.

## Residual risk

Anyone who can edit a Jenkins agent template can run the allowed image with any command, environment and network settings the create policy allows, and the agent can reach whatever its network reaches. The create policy bounds what the container can do to the host. It does not bound what runs inside it. Pin images by digest in `allowed_images` and restrict who can configure clouds and templates.

## Behavior notes

- Derived from jenkinsci/docker-plugin `1337.v3ca_fd1b_b_25ef` (the docker-java-api calls in `DockerTemplate`, `DockerCloud`, `DockerTransientNode`, `DockerContainerWatchdog`). Check the preset against the plugin source again when you upgrade it.
- The plugin's Docker API Version field is optional. Requests work bare or with a `/vX.Y` prefix.
- Ownership scopes list, inspect, stop and remove to containers created through this proxy. The plugin's watchdog finds containers by its own `JenkinsId` label, so it only ever sees its own agents.

## Usage

Set the Docker socket's group GID so sockguard can open `/var/run/docker.sock` (Linux: `stat -c '%g'`; macOS: `stat -f '%g'`):

```bash
case "$(uname -s)" in
  Linux) export DOCKER_SOCK_GID="$(stat -c '%g' /var/run/docker.sock)" ;;
  Darwin) export DOCKER_SOCK_GID="$(stat -f '%g' /var/run/docker.sock)" ;;
  *) echo "Unsupported host OS" >&2; exit 1 ;;
esac
docker compose up -d
# Jenkins: http://localhost:8080
```

## Hardening tips

- Add `clients.allowed_cidrs` to restrict which source IPs can reach the sockguard TCP listener within the Docker network.
- Switch to mTLS TCP (`listen.tls`), which the plugin supports through its Docker Host credentials.
- Add `require_memory_limit` and `require_pids_limit` to `container_create` if your templates set limits.
