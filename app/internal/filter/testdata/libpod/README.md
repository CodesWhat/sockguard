# libpod golden fixtures

Every `*.json` file in this directory is a **real** `POST /libpod/containers/create`
request body captured off the wire between the `podman` CLI client and a live
`podman system service` — not hand-written from documentation. Design doc
#148 (C4) requires this: the two prior design drafts disagreed on field names
(`ipc` vs `ipcns`), and SpecGenerator has drifted across Podman majors, so
this package's inspector, types, and tests are pinned against these captures
rather than either draft's guessed schema.

Two of them, `host_uts.json` and `host_cgroupns.json`, and every
`POST /libpod/pods/create` body under `pods/` were captured later and without a
daemon. See [Client-only captures](#client-only-captures) for how, and for why
the body is the same either way.

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

## Client-only captures

Captured 2026-10-07 for the host namespace gates 2.2.6 added:

```
Client:  Podman Engine 6.1.3  (darwin/arm64)
Server:  none
```

podman-remote builds a create body on the client. It fills a SpecGenerator or
a PodSpecGenerator from the command line and its own `containers.conf`,
marshals it, and sends it. Nothing the server says shapes the body, so these
were captured from the client alone: `podman --remote --url
unix:///tmp/sg-s76/capture.sock ...` pointed at a throwaway recorder that
answers `/libpod/_ping`, the image pull and the create, and writes down every
request body. The recorder isn't checked in. Each body was pretty-printed
with sorted keys, and no field was added, removed or renamed by hand.

The method was checked against the captures above. `podman create --name
sg-basic alpine:latest echo hi` recorded this way has the same keys as
`basic_create.json` from the live 5.8.1 server, and the same values apart from
the command it was given (`command`, and the command line echoed back in
`containerCreateCommand`). Past the container name and that command line,
`host_uts.json` differs from `host_pid.json` only in which namespace says
`host`.

What these don't show is anything the server does with the body. That's read
from Podman's source and cited next to the code.

| File | Command | What it pins |
|---|---|---|
| `host_uts.json` | `create --uts host` | `utsns: {"nsmode": "host"}`. Every other namespace stays `{}`. |
| `host_cgroupns.json` | `create --cgroupns host` | `cgroupns: {"nsmode": "host"}`. |
| `pods/default.json` | `pod create --name sg-pod` | What a pod create sends with no namespace flag: `pidns`, `ipcns` and `utsns` are `{"nsmode": "private"}`, `userns` and `netns` are `{}`, and `shared_namespaces` is `["ipc", "net", "uts"]`. There is no `cgroupns` key, because PodSpecGenerator has no such field. |
| `pods/pod_new.json` | `create --pod new:sg-pod-new alpine:latest echo hi` | The pod create that `run`/`create --pod new:NAME` sends first. `userns` is `{"nsmode": "default"}` and there's no `shared_namespaces`. |
| `pods/no_infra.json` | `pod create --infra=false` | `no_infra: true` with the same `private` namespaces and no `shared_namespaces`. |
| `pods/host_pid.json` | `pod create --pid host` | `pidns: {"nsmode": "host"}`. |
| `pods/path_pid.json` | `pod create --pid ns:/proc/1/ns/pid` | `pidns: {"nsmode": "path", "value": "/proc/1/ns/pid"}`. |
| `pods/host_uts.json` | `pod create --uts host` | `utsns: {"nsmode": "host"}`. |
| `pods/host_userns.json` | `pod create --userns host` | `userns: {"nsmode": "host"}`. |
| `pods/share_pid.json` | `pod create --share pid` | `shared_namespaces: ["pid"]`. |

`podman pod create` has no `--ipc` or `--cgroupns` flag. A pod's `ipcns` can
still be set by a client that writes the body itself, which is why it has a
gate, and a pod has no `cgroupns` to set.
