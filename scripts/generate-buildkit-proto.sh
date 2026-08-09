#!/usr/bin/env bash
# Regenerates the pinned BuildKit protobuf Go bindings under
# app/internal/buildkitproto/{control,pb,sourcepolicy,auth,secrets,
# sshforward,filesync,upload,fsutiltypes,health}/*.pb.go from the vendored
# .proto sources committed under app/internal/buildkitproto/proto/. See
# app/internal/buildkitproto/PROVENANCE.md for the upstream source URL, git
# tag, and sha256 of every vendored .proto file.
#
# Normal builds (`go build`, `go test`) never invoke this script — the
# generated .pb.go files are committed, so a plain checkout builds fully
# offline. This script exists only for deliberate compatibility bumps: bump
# the pinned tool versions and/or the vendored .proto sources, rerun it, and
# commit the resulting diff for review (issue #185 synthesis: a new Buildx
# minor "fails until a reviewed descriptor-manifest bump lands").
#
# Only two Go modules are used, both fetched via `go install <module>@<pinned
# version>` into a throwaway GOBIN so nothing here resolves @latest or
# touches the developer's normal GOBIN/PATH:
#   - google.golang.org/protobuf/cmd/protoc-gen-go — the ONLY code generator
#     invoked. protoc-gen-go-grpc is deliberately never installed or run:
#     the #185 sign-off is grpc-go, never, even in build tooling.
#   - github.com/bufbuild/buf/cmd/buf — a pure-Go protoc replacement (its
#     protocompile frontend parses/links .proto files without a C++ protoc
#     binary), used here purely as a local, offline-after-fetch compiler
#     front end. No BSR (Buf Schema Registry) network calls: every input is
#     the local proto/ directory and buf's built-in well-known types
#     (google/protobuf/timestamp.proto).
set -euo pipefail

PROTOC_GEN_GO_VERSION="v1.36.11" # keep in sync with go.mod's google.golang.org/protobuf
BUF_VERSION="v1.58.0"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PROTO_DIR="${REPO_ROOT}/app/internal/buildkitproto/proto"
OUT_ROOT="${REPO_ROOT}/app/internal/buildkitproto"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

GOBIN="${WORK_DIR}/bin"
mkdir -p "${GOBIN}"
echo "Installing pinned protoc-gen-go ${PROTOC_GEN_GO_VERSION} and buf ${BUF_VERSION} into ${GOBIN}..."
GOBIN="${GOBIN}" go install "google.golang.org/protobuf/cmd/protoc-gen-go@${PROTOC_GEN_GO_VERSION}"
GOBIN="${GOBIN}" go install "github.com/bufbuild/buf/cmd/buf@${BUF_VERSION}"

export PATH="${GOBIN}:${PATH}"

echo "Running buf generate against ${PROTO_DIR}..."
( cd "${PROTO_DIR}" && buf generate )

GEN_ROOT="${PROTO_DIR}/gen"

# Maps each buf-generated output path (mirrors the vendored proto/ tree,
# which mirrors upstream's fully-qualified import paths) to sockguard's flat,
# importable Go package layout. Only files sockguard actually vendors
# messages for appear here — see PROVENANCE.md for the full vendored list.
#
# A plain array of "src:dst" pairs rather than an associative array: macOS's
# preinstalled /bin/bash is 3.2 (no bash 4+ `declare -A` support), and this
# script has no other reason to require a newer bash.
FILE_MAP=(
  "github.com/moby/buildkit/api/services/control/control.pb.go:control/control.pb.go"
  "github.com/moby/buildkit/solver/pb/ops.pb.go:pb/ops.pb.go"
  "github.com/moby/buildkit/sourcepolicy/pb/policy.pb.go:sourcepolicy/policy.pb.go"
  "github.com/moby/buildkit/session/auth/auth.pb.go:auth/auth.pb.go"
  "github.com/moby/buildkit/session/secrets/secrets.pb.go:secrets/secrets.pb.go"
  "github.com/moby/buildkit/session/sshforward/ssh.pb.go:sshforward/ssh.pb.go"
  "github.com/moby/buildkit/session/filesync/filesync.pb.go:filesync/filesync.pb.go"
  "github.com/moby/buildkit/session/upload/upload.pb.go:upload/upload.pb.go"
  "github.com/tonistiigi/fsutil/types/wire.pb.go:fsutiltypes/wire.pb.go"
  "github.com/tonistiigi/fsutil/types/stat.pb.go:fsutiltypes/stat.pb.go"
  "grpc/health/v1/health.pb.go:health/health.pb.go"
)

for entry in "${FILE_MAP[@]}"; do
  src="${entry%%:*}"
  dst="${entry#*:}"
  mkdir -p "${OUT_ROOT}/$(dirname "${dst}")"
  cp "${GEN_ROOT}/${src}" "${OUT_ROOT}/${dst}"
  echo "  ${src} -> app/internal/buildkitproto/${dst}"
done

rm -rf "${GEN_ROOT}"

echo "Done. Review the diff, update PROVENANCE.md if any vendored .proto changed, and re-run:"
echo "  cd app && go build ./... && go test ./internal/buildkitproto/... ./internal/buildkitproxy/..."
