# Provenance: vendored BuildKit/fsutil/gRPC-health protobuf schemas

This package vendors a pinned, curated subset of the protobuf message
schemas moby/buildkit's gRPC surface uses on the two opaque tunnels sockguard
mediates (`POST /session` and `POST /grpc`), plus the standard gRPC health
check schema. See sockguard issue #185 for the full architecture; this
document exists so a future compatibility bump (a new BuildKit/Buildx
release) can mechanically verify what changed upstream before touching
`buildkitproxy`'s method-classification registry or any policy logic.

**Normal builds never fetch anything here.** The `.pb.go` files under
`control/`, `pb/`, `sourcepolicy/`, `auth/`, `secrets/`, `sshforward/`,
`filesync/`, `upload/`, `fsutiltypes/`, and `health/` are committed,
generated code — `go build`/`go test` just compile them like any other
package. Only `scripts/generate-buildkit-proto.sh`, run deliberately to bump
a pin, touches the network (to fetch the pinned `protoc-gen-go`/`buf` Go
tool versions — never to re-fetch the vendored `.proto` sources themselves,
which are already committed under `proto/`).

## How to read this table

- **Upstream source**: the exact URL the `.proto` file was fetched from.
- **Upstream tag**: the git tag/ref at that URL.
- **Upstream sha256**: sha256 of the byte-for-byte file as fetched, before
  any edit. Recompute this against a fresh fetch at the same tag to confirm
  upstream hasn't silently changed (tags are supposed to be immutable, but
  verify, don't assume).
- **Vendored sha256**: sha256 of the file as committed under `proto/` in
  this repo. `provenance_test.go` asserts this matches what's on disk, so a
  hand-edit without updating this table fails `go test`.
- **Curation**: `full` = byte-identical to upstream except the `go_package`
  option (always retargeted to this module — see below); `trimmed` = a
  documented subset of upstream's messages; `trimmed, dep dropped` = a
  documented subset AND a dependency (vtprotobuf) intentionally not carried
  forward.

## Why every file's `go_package` is retargeted

`protoc-gen-go` emits Go `import` statements from each file's `go_package`
option, not from where the `.proto` file physically sits in the module used
to generate it. Vendoring these files under
`github.com/codeswhat/sockguard/app/internal/buildkitproto/...` instead of
`github.com/moby/buildkit/...` means every vendored file's `go_package` had
to be rewritten to point here — otherwise the generated code's cross-package
imports (e.g. `control.proto` importing `pb.Definition` from `ops.proto`)
would reference a package this module doesn't provide. This is the **only**
change made to files marked `full` below; every message, field, comment, and
service definition is otherwise byte-for-byte upstream.

## Vendored files

| Vendored path (under `proto/`) | Go package | Upstream source | Upstream tag | Curation | Upstream sha256 | Vendored sha256 |
|---|---|---|---|---|---|---|
| `github.com/moby/buildkit/api/services/control/control.proto` | `control` | https://github.com/moby/buildkit/blob/v0.32.0/api/services/control/control.proto | `v0.32.0` | trimmed (see file header) | `0a187c5e92c24690d913b797953ddc8d901755ba52739e3ff776b10d0fd94614` | `8c6abff899ecec4d0cbc2224d7e1fb00415179d0b701955397b75303be6adcc3` |
| `github.com/moby/buildkit/solver/pb/ops.proto` | `pb` | https://github.com/moby/buildkit/blob/v0.32.0/solver/pb/ops.proto | `v0.32.0` | full | `309d9735d15cd945372a0dade3672cea19f94b61b6d0c05cf22856c608ff2a9c` | `1e015aded858583f7688621e43e142af9a0308d6742d7f636d8e1b74dd0ec4f5` |
| `github.com/moby/buildkit/sourcepolicy/pb/policy.proto` | `sourcepolicy` | https://github.com/moby/buildkit/blob/v0.32.0/sourcepolicy/pb/policy.proto | `v0.32.0` | full | `171bff4439bb69e16a12b808d9c09a5ca1da70ea267a08e9f94a7d4ffcd854fa` | `ba71e9a52c650723e0a4301efc13a79b9c8046de16471aff057b1fc5c8b7d96c` |
| `github.com/moby/buildkit/session/auth/auth.proto` | `auth` | https://github.com/moby/buildkit/blob/v0.32.0/session/auth/auth.proto | `v0.32.0` | full | `bb484658f71296efa1bdbe4977055c949e9d49ddfd5fff6b9d240d068e9e269d` | `09b949ed66ef011c117376a3dfdf328f4b734a6ee74259ba5562493805fddbeb` |
| `github.com/moby/buildkit/session/secrets/secrets.proto` | `secrets` | https://github.com/moby/buildkit/blob/v0.32.0/session/secrets/secrets.proto | `v0.32.0` | full | `0bec7c813157312d551ae881a36ddb08faf13eb042286c9fcc90c63148688150` | `7475254566bb8cd291f4222d322a01c235b46a9514aa1eb25175569ec57d4733` |
| `github.com/moby/buildkit/session/sshforward/ssh.proto` | `sshforward` | https://github.com/moby/buildkit/blob/v0.32.0/session/sshforward/ssh.proto | `v0.32.0` | full | `0277eb53c08696e785fcbe9ccc687fd32f28f906059518872aedcce2e4181aad` | `0c338d7aabda6b2aebd9e3a75dba8acfc362b4aa5c987fabdd14532cfda10606` |
| `github.com/moby/buildkit/session/filesync/filesync.proto` | `filesync` | https://github.com/moby/buildkit/blob/v0.32.0/session/filesync/filesync.proto | `v0.32.0` | full | `5bbdd3a8158c350cd2a75cc5925a020c0f5259542cf9c2cbe6c5c38a14c3fa3d` | `7c72ac356bd1f1f55c1b482487231802da7efc19cb03852f21d8d2c08e1cec2e` |
| `github.com/moby/buildkit/session/upload/upload.proto` | `upload` | https://github.com/moby/buildkit/blob/v0.32.0/session/upload/upload.proto | `v0.32.0` | full | `e0aaf9ca20ec2bf0b96545609a6efb83e35feca2f4c87d67fa40cacb0bd6dbee` | `6feb98a78551a85a8a2e42d2d0ee5d573c6eacb2143cf81e01f361719986d9d6` |
| `github.com/tonistiigi/fsutil/types/wire.proto` | `fsutiltypes` | https://github.com/moby/buildkit/blob/v0.32.0/vendor/github.com/tonistiigi/fsutil/types/wire.proto | `v0.32.0` (buildkit's vendored copy) | trimmed, dep dropped (see file header) | `bebd874ecae74b6e0e2e6f542bf54b8bf2254613fc13615948bce68b5297fa8a` | `a9ae5b41d629514b97541eb36db59de0686140fe1ff546b136ec0c7119058790` |
| `github.com/tonistiigi/fsutil/types/stat.proto` | `fsutiltypes` | https://github.com/moby/buildkit/blob/v0.32.0/vendor/github.com/tonistiigi/fsutil/types/stat.proto | `v0.32.0` (buildkit's vendored copy) | trimmed, dep dropped (see file header) | `80422956cb3741c83b4516e9d6ca931b4731ff3731b08e81309410d208c85d4c` | `9b0d11f3581a25f9caad122151cf238024d3af3a3d1a41e199e053704c5381f0` |
| `grpc/health/v1/health.proto` | `health` (proto package `grpc.health.v1`) | https://github.com/grpc/grpc/blob/v1.71.0/src/proto/grpc/health/v1/health.proto | `v1.71.0` | full | `8d44f54645557c1e10ba0da377883fd4d24ad994aff4f2139d61b7e9f0ece511` | `4fd3e7fd85d5ffe6a6e4952756b7599f432c4f1d907fa29101a15f7d4e257f76` |

Notes:

- `fsutiltypes/{wire,stat}.proto` are fetched from BuildKit's own vendored
  copy (`vendor/github.com/tonistiigi/fsutil/...`) at the same `v0.32.0` tag,
  rather than from `tonistiigi/fsutil` directly, so the wire schema matches
  exactly what BuildKit v0.32.0 actually serializes over `FileSync.DiffCopy`
  /`FileSync.TarStream`/`FileSend.DiffCopy`.
- `control.proto`'s trim removes `DiskUsage`/`Prune`/`ListWorkers`/`Info`/
  `ListenBuildHistory`/`UpdateBuildHistory` and their message types — none of
  those methods need a decoded message (`ListWorkers`/`Info` are
  Passthrough, forwarded without inspection; the rest are Deny, rejected
  before any attempt to unmarshal). Only `Solve`/`Status` and their
  transitive types (`pb.Definition` and friends from `ops.proto`,
  `sourcepolicy.Policy`) are kept. See the file's own header comment for the
  exhaustive removed-message list.
- `fsutiltypes/*.proto`'s trim removes the
  `import "github.com/planetscale/vtprotobuf/vtproto/ext.proto"` line and
  the `(vtproto.mempool)` message option: sockguard's generation only ever
  runs plain `protoc-gen-go` (see `scripts/generate-buildkit-proto.sh`),
  never vtprotobuf's `protoc-gen-go-vtproto`, and adding a dependency on
  vtprotobuf's extension descriptor for an annotation nothing here consumes
  would be a pointless supply-chain addition on a path the #185 sign-off
  scoped to exactly `golang.org/x/net/http2` (phase 2) and
  `google.golang.org/protobuf` — nothing else, ever.
- Every vendored `.proto` file's `go_package` option points into this
  module (`github.com/codeswhat/sockguard/app/internal/buildkitproto/...`)
  rather than upstream's own module path — see "Why every file's
  `go_package` is retargeted" above. `sourcepolicy/pb/policy.proto` and
  `grpc/health/v1/health.proto` additionally get a shorter Go package alias
  (`sourcepolicy`, `health`) in place of upstream's
  `moby_buildkit_v1_sourcepolicy`/`grpc_health_v1`, purely for import
  ergonomics — no schema content changed.

## Deliberately NOT vendored (message types)

The #185 synthesis classifies these services/methods as **Deny** — rejected
by `buildkitproxy.Classify` before any attempt to decode a payload — so no
message types are generated for them. Only their fully-qualified method
names appear (as plain Go string literals) in
`buildkitproxy/registry.go`'s `DeniedExamples`, sourced from:

- `frontend/gateway/pb/gateway.proto` (`LLBBridge` service) —
  https://github.com/moby/buildkit/blob/v0.32.0/frontend/gateway/pb/gateway.proto
- `session/exporter/exporter.proto` (`Exporter` service, negotiation) —
  https://github.com/moby/buildkit/blob/v0.32.0/session/exporter/exporter.proto
- `sourcepolicy/policysession/policysession.proto` (`PolicyVerifier`
  service) —
  https://github.com/moby/buildkit/blob/v0.32.0/sourcepolicy/policysession/policysession.proto
- `containerd.services.content.v1.Content` (containerd's content-store gRPC
  service, method names are stable/well-known:
  `Info`/`Update`/`List`/`Delete`/`Read`/`Write`/`Status`/`ListStatuses`/
  `Abort`) — not part of the moby/buildkit repo; classified by name only.
- `opentelemetry.proto.collector.trace.v1.TraceService/Export` — the
  standard OTLP trace-export RPC; not part of the moby/buildkit repo;
  classified by name only.

Also intentionally not vendored: `moby.buildkit.v1.Control/Session`, the
nested bidirectional-stream method on the *same* `Control` service whose
`Solve`/`Status` messages ARE vendored above — its `BytesMessage` request/
response type is trivial (`bytes data = 1;`) but the method itself is
Deny-by-default (opaque nested tunnel), so it never needs decoding.

## Regenerating

Run `scripts/generate-buildkit-proto.sh` (pinned `buf`/`protoc-gen-go`
versions documented in the script header). It only ever reads
`proto/` and writes the `.pb.go` files listed in its `FILE_MAP`; it never
re-fetches `.proto` sources. Bumping to a new upstream BuildKit release
means: re-fetch the relevant `.proto` files at the new tag, diff them
against this table's upstream URLs, apply the same trims/retargets
documented above, update this table's hashes, rerun the script, and — per
the #185 synthesis — treat every added/changed/removed method as a reviewed
classification decision in `buildkitproxy/registry.go`, never a silent
carry-forward.
