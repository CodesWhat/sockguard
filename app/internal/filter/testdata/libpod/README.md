# libpod golden fixtures

Every `*.json` file in this directory is a **real** `POST /libpod/containers/create`
request body captured off the wire between the `podman` CLI client and a live
`podman system service` — not hand-written from documentation. Design doc
#148 (C4) requires this: the two prior design drafts disagreed on field names
(`ipc` vs `ipcns`), and SpecGenerator has drifted across Podman majors, so
this package's inspector, types, and tests are pinned against these captures
rather than either draft's guessed schema.

## Provenance

Captured 2026-08-05 via a real Podman machine on macOS (`applehv` backend):

```
Client:  Podman Engine 6.0.2  (darwin/arm64, go1.26.5)
Server:  Podman Engine 5.8.1  (linux/arm64, fedora-coreos 43, go1.25.7)
```

The client reports its own version in the request path
(`/v6.0.2/libpod/containers/create`); the body shape itself is produced and
served by the **5.8.1 server** (SpecGenerator on the podman-machine-default
VM), which is the version that matters for wire-shape fidelity. Both numbers
are recorded here since a client/server version straddle is exactly the kind
of thing that can shift field names between Podman releases.

## Capture method

`podman machine start` was used to bring up a real `podman system service`
socket (forwarded to the host as
`$TMPDIR/podman/podman-machine-default-api.sock`). A small Python
`asyncio` unix-socket-to-unix-socket proxy
(`unixproxy.py`, not checked in — throwaway tooling) sat in front of that
socket, logging every client→server byte stream to a file while forwarding
traffic unmodified. The `podman` CLI was then pointed at the proxy socket via
`--url unix:///tmp/sg148/proxy.sock` and driven through `podman create` /
`podman volume create` for each scenario below. The raw HTTP/1.1 byte capture
was parsed offline (matching `Content-Length` framing) to recover exact
request bodies for every `.../libpod/containers/create` call, which were then
pretty-printed (`json.dumps(..., indent=2, sort_keys=True)`) and committed
byte-faithfully aside from formatting. No field was added, removed, or
renamed by hand.

This is real-socket capture, not source-derived: every fixture below reflects
what SpecGenerator's client-side request builder actually put on the wire for
Podman 6.0.2 talking to a 5.8.1 engine.

## Fixtures

| File | Command | What it pins |
|---|---|---|
| `basic_create.json` | `podman create --name X alpine:latest echo hello` | Baseline shape: every field SpecGenerator sends even with no options, all default-empty namespace objects (`netns`, `pidns`, `ipcns`, `userns`, `utsns`, `cgroupns` all `{}`). |
| `privileged.json` | `--privileged` | Top-level `privileged: true` (bool, not nested). |
| `host_network.json` | `--network host` | `netns: {"nsmode": "host"}` — confirms the `{nsmode, value}` shape and the field name `netns` (not `network_ns` or similar). |
| `host_pid.json` | `--pid host` | `pidns: {"nsmode": "host"}`. |
| `host_ipc.json` | `--ipc host` | `ipcns: {"nsmode": "host"}` — **resolves the C4 ipc/ipcns conflict: it's `ipcns`.** |
| `host_userns.json` | `--userns host` | `userns: {"nsmode": "host"}`. |
| `namespace_share_container_ref.json` | `--network container:<name>` | `netns: {"nsmode": "container", "value": "<name>"}` — confirms the container-ref sharing shape used for the `RestrictNamespaceSharing`-equivalent gate. |
| `mounts_bind_tmpfs.json` | `-v /tmp/bindsrc:/data:ro --mount type=tmpfs,destination=/tmp/x` | `mounts: [{type, source, destination, options}]` (all lowercase keys) for bind + tmpfs mounts. |
| `volumes_named.json` | `-v sg-vol:/data` (named volume) | `volumes: [{Name, Dest, Options, SubPath, IsAnonymous}]` — **note the field-name casing is capitalized here, unlike `mounts`.** This is a genuine SpecGenerator inconsistency between the two arrays, not a typo; the inspector's volume-decode struct must match it exactly. |
| `devices.json` | `--device /dev/null:/dev/xnull` | `devices: [{path, type, major, minor}]`; `path` carries the raw, unsplit `"src:dst"` string as given on the CLI — SpecGenerator does not pre-split it client-side. |
| `capabilities.json` | `--cap-add SYS_ADMIN --cap-drop NET_RAW` | `cap_add` / `cap_drop`: `[]string`. |
| `security_opts_seccomp_apparmor_selinux.json` | `--security-opt seccomp=unconfined --security-opt apparmor=unconfined --security-opt label=disable` | `seccomp_policy` + `seccomp_profile_path`, `apparmor_profile`, `selinux_opts: []string`. |
| `resource_limits.json` | `--memory 128m --cpus 1.5 --pids-limit 100` | `resource_limits.memory.{limit,swap}`, `resource_limits.cpu.{period,quota}`, `resource_limits.pids.limit`. |
| `resource_limits_cpu_shares.json` | `--cpu-shares 512` | `resource_limits.cpu.shares` — captured separately since `--cpus` and `--cpu-shares` populate different `cpu` sub-fields. |
| `systemd_mode.json` | `--systemd=always` | Top-level `systemd: "always"` (string, not bool — matches Docker-adjacent tri-state semantics: `"true"`/`"false"`/`"always"`). |
| `idmappings.json` | `--uidmap 0:100000:65536 --gidmap 0:100000:65536` | `idmappings.{UIDMap,GIDMap}: [{container_id, host_id, size}]`, plus `HostUIDMapping`/`HostGIDMapping`/`AutoUserNs`/`AutoUserNsOpts`. |
| `labels.json` | `--label foo=bar --label sockguard.owner=team-a` | Top-level `labels: map[string]string` (lowercase key — the mutator must inject lowercase `labels`, never `Labels`, per design C6). |
| `sysctls.json` | `--sysctl net.ipv4.ip_forward=1` | Field name is **`sysctl`** (singular), not `sysctls`. |
| `read_only_filesystem.json` | `--read-only` | Top-level `read_only_filesystem: bool`. |
| `user.json` | `--user 1000:1000` | Top-level `user: string` (`"uid:gid"` form, not split fields). |

## Confirmed field-name resolutions (design doc C4)

These were the specific points the two independent design drafts disagreed
on or left unverified; the fixtures above are the tiebreaker:

- **IPC namespace field is `ipcns`**, not `ipc` — see `host_ipc.json`.
- Namespace-sharing objects are uniformly `{"nsmode": "...", "value": "..."}`
  across `netns`/`pidns`/`ipcns`/`userns`/`utsns`/`cgroupns` — see
  `namespace_share_container_ref.json`.
- `mounts` (bind/tmpfs/image mounts) and `volumes` (named-volume mounts) are
  **two separate top-level arrays with different key casing** — lowercase in
  `mounts`, capitalized in `volumes`. A decoder that assumes one shape for
  both will silently miss the other.
- The sysctl field is singular: `sysctl`, not `sysctls`.
- `devices[].path` is the raw unsplit `"host:container[:perms]"` string.
