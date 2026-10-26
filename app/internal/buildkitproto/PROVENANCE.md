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
`filesync/`, `upload/`, `fsutiltypes/`, `health/`, `gateway/`, `worker/`, and `caps/` are committed,
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
`github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/...` instead of
`github.com/moby/buildkit/...` means every vendored file's `go_package` had
to be rewritten to point here — otherwise the generated code's cross-package
imports (e.g. `control.proto` importing `pb.Definition` from `ops.proto`)
would reference a package this module doesn't provide. This is the **only**
change made to files marked `full` below; every message, field, comment, and
service definition is otherwise byte-for-byte upstream.

## Vendored files

| Vendored path (under `proto/`) | Go package | Upstream source | Upstream tag | Curation | Upstream sha256 | Vendored sha256 |
|---|---|---|---|---|---|---|
| `github.com/moby/buildkit/api/services/control/control.proto` | `control` | https://github.com/moby/buildkit/blob/v0.32.0/api/services/control/control.proto | `v0.32.0` | trimmed (see file header) | `0a187c5e92c24690d913b797953ddc8d901755ba52739e3ff776b10d0fd94614` | `8f60c8592555c2d2724463fa9deaff4e2fc0572a3ec5140ac9f500b2f9e65d8a` |
| `github.com/moby/buildkit/solver/pb/ops.proto` | `pb` | https://github.com/moby/buildkit/blob/v0.32.0/solver/pb/ops.proto | `v0.32.0` | full | `309d9735d15cd945372a0dade3672cea19f94b61b6d0c05cf22856c608ff2a9c` | `3b39e65013eeac73e79f3d389876364deb4788ca4bead126329b5da39bbda76a` |
| `github.com/moby/buildkit/sourcepolicy/pb/policy.proto` | `sourcepolicy` | https://github.com/moby/buildkit/blob/v0.32.0/sourcepolicy/pb/policy.proto | `v0.32.0` | full | `171bff4439bb69e16a12b808d9c09a5ca1da70ea267a08e9f94a7d4ffcd854fa` | `805c2f0f355ffa63077100c2237aeac349d73ce56a762a37a8c69aeb0ebd5510` |
| `github.com/moby/buildkit/session/auth/auth.proto` | `auth` | https://github.com/moby/buildkit/blob/v0.32.0/session/auth/auth.proto | `v0.32.0` | full | `bb484658f71296efa1bdbe4977055c949e9d49ddfd5fff6b9d240d068e9e269d` | `96877cb2d6d988f1cb0249a9a4752ad16a4418b7569de7726fbdcdb889b65314` |
| `github.com/moby/buildkit/session/secrets/secrets.proto` | `secrets` | https://github.com/moby/buildkit/blob/v0.32.0/session/secrets/secrets.proto | `v0.32.0` | full | `0bec7c813157312d551ae881a36ddb08faf13eb042286c9fcc90c63148688150` | `791357c9c61acfd6e95bb62285000b0a8ea8e5ee508cb676bd646e762467b24c` |
| `github.com/moby/buildkit/session/sshforward/ssh.proto` | `sshforward` | https://github.com/moby/buildkit/blob/v0.32.0/session/sshforward/ssh.proto | `v0.32.0` | full | `0277eb53c08696e785fcbe9ccc687fd32f28f906059518872aedcce2e4181aad` | `fa2423010f4e9ef8784a5d09f8330da58de602eafcbefb57a00b0446f8d956ea` |
| `github.com/moby/buildkit/session/filesync/filesync.proto` | `filesync` | https://github.com/moby/buildkit/blob/v0.32.0/session/filesync/filesync.proto | `v0.32.0` | full | `5bbdd3a8158c350cd2a75cc5925a020c0f5259542cf9c2cbe6c5c38a14c3fa3d` | `1b9360aba32f1c630dbee325c1d0c1261d4a3c313c32a7baa9191f4fd878e807` |
| `github.com/moby/buildkit/session/upload/upload.proto` | `upload` | https://github.com/moby/buildkit/blob/v0.32.0/session/upload/upload.proto | `v0.32.0` | full | `e0aaf9ca20ec2bf0b96545609a6efb83e35feca2f4c87d67fa40cacb0bd6dbee` | `79743ff02a341ca0ab34da5bf61e12525f17fc52f8cc952c70d92a59382bb265` |
| `github.com/tonistiigi/fsutil/types/wire.proto` | `fsutiltypes` | https://github.com/moby/buildkit/blob/v0.32.0/vendor/github.com/tonistiigi/fsutil/types/wire.proto | `v0.32.0` (buildkit's vendored copy) | trimmed, dep dropped (see file header) | `bebd874ecae74b6e0e2e6f542bf54b8bf2254613fc13615948bce68b5297fa8a` | `6084471550211900a233fbcf08440dad3ec1fa2e450e57d0aece8c83e2524931` |
| `github.com/tonistiigi/fsutil/types/stat.proto` | `fsutiltypes` | https://github.com/moby/buildkit/blob/v0.32.0/vendor/github.com/tonistiigi/fsutil/types/stat.proto | `v0.32.0` (buildkit's vendored copy) | trimmed, dep dropped (see file header) | `80422956cb3741c83b4516e9d6ca931b4731ff3731b08e81309410d208c85d4c` | `964e5788abd96dc6c5e02986ba6083005329808be6950b6c494f0762824c8f14` |
| `grpc/health/v1/health.proto` | `health` (proto package `grpc.health.v1`) | https://github.com/grpc/grpc/blob/v1.71.0/src/proto/grpc/health/v1/health.proto | `v1.71.0` | full | `8d44f54645557c1e10ba0da377883fd4d24ad994aff4f2139d61b7e9f0ece511` | `46f8b3bfc81963d98d0f5a7a29df485184fce2b8495a7bcd47666764f69a54cb` |
| `github.com/moby/buildkit/frontend/gateway/pb/gateway.proto` | `gateway` | https://github.com/moby/buildkit/blob/v0.32.0/frontend/gateway/pb/gateway.proto | `v0.32.0` | full | `cc3bf88b551578c859c2985a6157a9f725ebe49181bd92220c91d3f89c659287` | `9cb0dcc2696816cb558929a3573c88074a6622c24a43e7c8621e901482b254a9` |
| `github.com/moby/buildkit/api/types/worker.proto` | `worker` | https://github.com/moby/buildkit/blob/v0.32.0/api/types/worker.proto | `v0.32.0` | full | `fcae6456534010fc6afdf8440dfa3d8fad5677734e456778fcf1ad23c22194f5` | `f314ffb5935e78a468724392cb05e88266c444d77735bcf6679e0ab5ee102dfc` |
| `github.com/moby/buildkit/util/apicaps/pb/caps.proto` | `caps` | https://github.com/moby/buildkit/blob/v0.32.0/util/apicaps/pb/caps.proto | `v0.32.0` | full | `1cb3824b0daabf5b57de609d17b5d785a6d474c240e93185d2fafa5a2f04de89` | `fe00b7f4e7f7f993c0c792796cd41488acbdf318088104af0ed5d8cc562b78be` |
| `google/rpc/status.proto` | `status (generation dependency)` | https://github.com/googleapis/googleapis/blob/a68d4433fa8f0cf72710a60cc09dec096db0fcee/google/rpc/status.proto | `a68d4433fa8f0cf72710a60cc09dec096db0fcee` | full | `f5bfd262e6705c7ae73f32e0ad8ee20ce8c0a2578df8c4f76ebf76b572f295ed` | `f5bfd262e6705c7ae73f32e0ad8ee20ce8c0a2578df8c4f76ebf76b572f295ed` |

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
  module (`github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/...`)
  rather than upstream's own module path — see "Why every file's
  `go_package` is retargeted" above. `sourcepolicy/pb/policy.proto` and
  `grpc/health/v1/health.proto` additionally get a shorter Go package alias
  (`sourcepolicy`, `health`) in place of upstream's
  `moby_buildkit_v1_sourcepolicy`/`grpc_health_v1`, purely for import
  ergonomics — no schema content changed.

## Gateway schema dependencies

The full v0.32.0 gateway, worker, and capability schemas support mediation of external frontend RPCs. Vendoring a schema does not admit its methods. Container creation and process execution remain denied until explicitly implemented.

`google/rpc/status.proto` is an unchanged, pinned generation dependency. Its `go_package` intentionally remains the official package already present in the Go module graph. The generator does not copy a local Status binding: registering a second `google.rpc.Status` descriptor would conflict with the existing Sigstore dependency. Gateway bindings import the existing message type, without adding a gRPC server or client library.

## Deliberately NOT vendored (message types)

The #185 synthesis classifies these services/methods as **Deny** — rejected
by `buildkitproxy.Classify` before any attempt to decode a payload — so no
message types are generated for them. Only their fully-qualified method
names appear (as plain Go string literals) in
`buildkitproxy/registry.go`'s `DeniedExamples`, sourced from:

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
