// Package buildkitproto holds pinned, vendored protobuf message types for
// the subset of BuildKit's (and its transitive fsutil/gRPC-health)
// schemas sockguard's BuildKit gRPC mediator needs — see issue #185.
//
// Every .pb.go file under this tree is committed, generated code produced
// by ../../../scripts/generate-buildkit-proto.sh from the vendored .proto
// sources under proto/. Normal builds never regenerate anything here; see
// PROVENANCE.md for exactly which upstream files were vendored, at what
// git tag, with what sha256, and — for the files that aren't byte-for-byte
// upstream — precisely what was trimmed and why.
//
// This package is intentionally free of any non-protobuf runtime
// dependency: only google.golang.org/protobuf and the Go standard library.
// It must never import grpc-go — the #185 sign-off's dependency exception
// covers google.golang.org/protobuf (this package) and golang.org/x/net/http2
// (the phase 2 transport, elsewhere), nothing else.
//
//go:generate bash ../../../scripts/generate-buildkit-proto.sh
package buildkitproto
