# Sockguard + Portwing + drydock

**Who this is for:** Teams running the full tri-tool topology — [Portwing](https://github.com/CodesWhat/portwing) as a remote Docker agent reporting into [drydock](https://github.com/CodesWhat/drydock) — and wanting to eliminate the raw Docker socket mount from both the Portwing and drydock containers.

**What's exposed:** A unix socket shared via a named volume. Portwing connects to `/var/run/sockguard/sockguard.sock` instead of `/var/run/docker.sock`. drydock never sees a Docker socket at all — every container/image fact comes secondhand, already filtered by sockguard. The default `docker-compose.yml` connects the two over HTTP in **Standard Mode** (drydock is the controller, Portwing is the agent; port 4000 is the Portwing API, port 3000 is the drydock web UI). `docker-compose.edge-exec.yml` instead runs Portwing in **Edge Mode**, dialing out to drydock over a WebSocket — see "Choosing a variant" below.

This bundle ships two variants — both default to the audited Sockguard 1.5.1, Portwing 0.8.1, and drydock 1.5.2 releases. Override `SOCKGUARD_VERSION`, `PORTWING_VERSION`, or `DRYDOCK_VERSION` deliberately when validating an upgrade.

## Choosing a variant

| | `docker-compose.yml` (default) | `docker-compose.edge-exec.yml` |
|---|---|---|
| Portwing mode | Standard Mode — drydock (controller) polls Portwing (agent) over HTTP | Edge Mode — Portwing dials **out** to drydock over a WebSocket |
| sockguard preset | `sockguard.yaml` (copy of `portwing.yaml`) | `sockguard-with-exec.yaml` (copy of `portwing-with-exec.yaml`) |
| Exec (interactive terminal through Portwing) | **Not available** — Standard Mode has no exec transport | Available — exec is multiplexed over the same WebSocket as container sync |
| Authentication | Shared secret (`TOKEN_FILE` / `DD_AGENT_PORTWING_SECRET__FILE`) | Ed25519 public-key challenge-response (`PRIVATE_KEY_FILE` + registered pubkey) |
| Needs inbound Portwing port | Yes (`4000`) | No — Portwing only dials out |
| Use when | Hosts drydock can reach directly and exec isn't needed | Hosts behind NAT/firewall, or you need drydock-driven exec sessions |

**Exec is an Edge Mode feature.** Portwing's WebSocket connection multiplexes container-sync and exec frames together; Standard Mode's HTTP polling has no exec transport at all. Swapping `sockguard.yaml` for `sockguard-with-exec.yaml` under the default `docker-compose.yml` only unlocks exec *at the sockguard layer* — drydock still can't reach it without the Edge Mode wiring, so use `docker-compose.edge-exec.yml` for exec, not a partial swap of the default stack.

Portwing Edge's WebSocket dial-out is stable and enabled by default as of drydock 1.6; the pinned drydock 1.5.2 default in `docker-compose.edge-exec.yml` still works but treats it as experimental, so that file sets `DD_EXPERIMENTAL_PORTWING=true` explicitly — drop it once `DRYDOCK_VERSION` is bumped to 1.6+.

As of Portwing's next release after 0.8.1, exec-denial reasons (privileged exec, a command outside `allowed_commands`, a non-root-user policy violation, etc.) surface all the way through to drydock's controller-side errors instead of a bare failure — see `docker-compose.edge-exec.yml`'s header for the wiring that carries them.

## Security tradeoffs

This table describes the default `docker-compose.yml` (Standard Mode, no exec). `docker-compose.edge-exec.yml` swaps the "Portwing<->drydock shared secret" row for Ed25519 key registration and the "Exec denied" row to "Exec allowed" (with the `allow_privileged: false` / `allow_root_user: true` policy from `sockguard-with-exec.yaml` still enforced) — everything else in the table applies to both variants.

| Control | Status |
|---|---|
| sockguard: `read_only`, `cap_drop: ALL`, `no-new-privileges` | Enabled |
| Portwing: `read_only`, `cap_drop: ALL`, `no-new-privileges`, explicit non-root `user` | Enabled |
| drydock: hardened rootfs/user | Not applied — drydock's entrypoint provisions `/store` as root, then drops privileges itself via `su-exec`; matches this repo's existing `examples/compose/drydock/` |
| No raw socket in Portwing container | Yes — named volume unix socket |
| No Docker socket in drydock container at all | Yes — drydock only ever talks to Portwing's HTTP API |
| Portwing<->drydock shared secret | Required — a generated token, mounted as a Docker secret into both containers (`TOKEN_FILE` / `DD_AGENT_PORTWING_SECRET__FILE`), never in plaintext env |
| Exec denied | Yes |
| Build denied | Yes |
| Log streaming allowed; raw archive/export/attach denied | `insecure_allow_read_exfiltration: true` (required for Portwing's `GetContainerLogs()`; `/containers/*/archive`, `/export`, `/attach` stay denied) |
| Image pulls | All registries allowed (Portwing tracks arbitrary images) |
| Bind mounts on container create | Denied unless you add paths to `allowed_bind_mounts` |
| Response redaction (env, mounts, network topology) | Disabled — required for drydock passthrough topology |
| Portwing<->drydock transport | Plain HTTP over the compose network (`DD_AGENT_ALLOW_INSECURE_SECRET=true`); use TLS for any cross-host deployment |
| drydock dashboard authentication | Anonymous only for this loopback-bound local example (`DD_ANONYMOUS_AUTH_CONFIRM=true`); configure Basic Auth or OIDC before exposing it beyond the host |

## Redaction note

The Portwing preset disables `redact_mount_paths`, `redact_container_env`, and `redact_network_topology` because in this tri-tool topology (sockguard → Portwing → drydock) Portwing forwards container inspect data to drydock, which uses it to recreate containers during updates. If sockguard redacts those fields, drydock cannot reconstruct the original container spec.

If you run Portwing without drydock, re-enable redactions by editing `sockguard.yaml`:

```yaml
response:
  redact_mount_paths: true
  redact_container_env: true
  redact_network_topology: true
```

## Compatibility boundary: remote updates are not implemented yet

Portwing's Standard Mode agent doesn't implement the update-trigger endpoints yet — `POST /api/triggers/{type}/{name}` (and `.../batch`) return `501`. Edge mode securely tunnels Docker reads, lifecycle calls, logs, events, metrics, and configured exec, but the current `portwing/1.0` protocol still returns empty watcher/trigger responses and drydock does not route its remote watcher or trigger methods through the Edge adapter. In either mode, drydock can discover the agent and consume its container state, but it cannot currently push an update through Portwing. Keep the updater local to the daemon, or use another explicitly authorized controller, until the watcher/trigger contract lands in both repositories.

## Usage: Standard Mode (`docker-compose.yml`, default)

Set the Docker socket's group GID so sockguard can open `/var/run/docker.sock` (Linux: `stat -c '%g'`; macOS: `stat -f '%g'`), and generate the shared Portwing<->drydock secret:

```bash
export DOCKER_SOCK_GID=$(stat -c '%g' /var/run/docker.sock)  # macOS: stat -f '%g'
openssl rand -hex -out portwing_token.txt 32
sudo chown 65532:65532 portwing_token.txt && sudo chmod 0400 portwing_token.txt
docker compose up -d
# Portwing API: http://localhost:4000
# drydock UI:   http://localhost:3000
```

drydock should log `Handshake successful. Received N containers.` for the `portwing` agent once it connects. If it doesn't, check `docker compose logs drydock` — a `401` means the secret file didn't match on both sides; `ECONNREFUSED` means Portwing isn't up yet.

To allowlist bind mounts for containers Portwing recreates, add host paths to `sockguard.yaml` under `request_body.container_create.allowed_bind_mounts`.

This variant has no exec transport — see the next section for exec sessions through Portwing.

## Usage: Edge Mode + exec (`docker-compose.edge-exec.yml`)

Use this variant on hosts drydock can't reach directly (NAT, firewall), or whenever you need drydock-driven interactive exec sessions through Portwing. Set the socket GID as above, then generate Portwing's Ed25519 keypair and register the printed public key with drydock:

```bash
export DOCKER_SOCK_GID=$(stat -c '%g' /var/run/docker.sock)  # macOS: stat -f '%g'
portwing keygen -comment "tri-tool-edge-host" > portwing_ed25519.pem
sudo chown 65532:65532 portwing_ed25519.pem && sudo chmod 0400 portwing_ed25519.pem

# portwing keygen prints the private key (saved above) followed by an
# authorized_keys-format public-key line — append that printed line to
# portwing_authorized_keys so drydock preloads it via DD_PORTWING_AUTHORIZED_KEYS:
echo "ed25519 <paste-the-printed-pubkey-line-here>" >> portwing_authorized_keys

docker compose -f docker-compose.edge-exec.yml up -d
# drydock UI: http://localhost:3000
```

drydock should log the same `Handshake successful. Received N containers.` line for the `tri-tool-edge-host` agent once Portwing dials in. If it doesn't: a `bad-signature` or `unknown-key` error frame means `portwing_authorized_keys` doesn't contain the key Portwing is presenting (re-run `portwing keygen` and re-append its output, or register the key live with `POST /api/v1/portwing/keys` instead); `ECONNREFUSED` from Portwing means drydock isn't up yet.

Exec sessions driven from drydock's UI are allowed by `sockguard-with-exec.yaml`'s `allow_privileged: false` / `allow_root_user: true` policy — a privileged exec attempt is denied at sockguard regardless of what Portwing or drydock request. As of Portwing's next release after 0.8.1, that denial reason (and other exec-policy denials) surfaces in drydock's controller-side error output instead of a bare failure, so you can tell "sockguard denied this" apart from "the container doesn't exist" or "Portwing is unreachable."

To allowlist bind mounts for containers Portwing recreates, add host paths to `sockguard-with-exec.yaml` under `request_body.container_create.allowed_bind_mounts`. For the full bundled-preset list see the main README's [bundled presets](../../../README.md#bundled-presets-17) section.
