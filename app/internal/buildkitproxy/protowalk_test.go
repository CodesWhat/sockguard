package buildkitproxy

import (
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/codeswhat/sockguard/internal/buildkitproto/control"
	"github.com/codeswhat/sockguard/internal/buildkitproto/pb"
)

// unknownFieldBytes builds a minimal valid protobuf wire encoding of a
// single varint-typed field at a field number ("9999") no vendored
// descriptor in this repo declares, for use as SetUnknown input marking a
// message as carrying unknown-field bytes.
func unknownFieldBytes() protoreflect.RawFields {
	b := protowire.AppendTag(nil, 9999, protowire.VarintType)
	b = protowire.AppendVarint(b, 1)
	return protoreflect.RawFields(b)
}

func TestHasUnknownFields(t *testing.T) {
	t.Run("nil interface", func(t *testing.T) {
		var m proto.Message
		if hasUnknownFields(m) {
			t.Fatal("nil proto.Message must report no unknown fields")
		}
	})

	t.Run("typed nil pointer", func(t *testing.T) {
		if hasUnknownFields((*control.StatusRequest)(nil)) {
			t.Fatal("typed-nil message must report no unknown fields")
		}
	})

	t.Run("clean message with nested messages, maps, and lists", func(t *testing.T) {
		req := &control.SolveRequest{
			Ref:      "ref",
			Frontend: "dockerfile.v0",
			FrontendAttrs: map[string]string{
				"filename": "Dockerfile",
			},
			Entitlements: []string{"network.host"},
			Cache: &control.CacheOptions{
				Exports: []*control.CacheOptionsEntry{
					{Type: "registry", Attrs: map[string]string{"ref": "example.com/foo"}},
				},
				Imports: []*control.CacheOptionsEntry{
					{Type: "registry", Attrs: map[string]string{"ref": "example.com/bar"}},
				},
			},
			Exporters: []*control.Exporter{
				{Type: "image", Attrs: map[string]string{"name": "example.com/img"}},
			},
			FrontendInputs: map[string]*pb.Definition{
				"context": {Def: [][]byte{{0x01}}},
			},
		}
		if hasUnknownFields(req) {
			t.Fatal("clean message must report no unknown fields")
		}
	})

	t.Run("top-level unknown field", func(t *testing.T) {
		req := &control.SolveRequest{Ref: "ref"}
		req.ProtoReflect().SetUnknown(unknownFieldBytes())
		if !hasUnknownFields(req) {
			t.Fatal("top-level unknown field bytes must be detected")
		}
	})

	t.Run("unknown field one level deep in a plain message field", func(t *testing.T) {
		req := &control.SolveRequest{Cache: &control.CacheOptions{}}
		req.Cache.ProtoReflect().SetUnknown(unknownFieldBytes())
		if !hasUnknownFields(req) {
			t.Fatal("unknown field bytes nested in Cache must be detected")
		}
	})

	t.Run("unknown field in a repeated message list element", func(t *testing.T) {
		req := &control.SolveRequest{
			Exporters: []*control.Exporter{
				{Type: "image"},
				{Type: "local"},
			},
		}
		req.Exporters[1].ProtoReflect().SetUnknown(unknownFieldBytes())
		if !hasUnknownFields(req) {
			t.Fatal("unknown field bytes in a non-first list element must be detected")
		}
	})

	t.Run("unknown field in a map message value", func(t *testing.T) {
		req := &control.SolveRequest{
			FrontendInputs: map[string]*pb.Definition{
				"context": {},
			},
		}
		req.FrontendInputs["context"].ProtoReflect().SetUnknown(unknownFieldBytes())
		if !hasUnknownFields(req) {
			t.Fatal("unknown field bytes in a map value message must be detected")
		}
	})

	t.Run("unknown field two levels deep via list within a message field", func(t *testing.T) {
		req := &control.SolveRequest{
			Cache: &control.CacheOptions{
				Exports: []*control.CacheOptionsEntry{
					{Type: "registry"},
				},
			},
		}
		req.Cache.Exports[0].ProtoReflect().SetUnknown(unknownFieldBytes())
		if !hasUnknownFields(req) {
			t.Fatal("unknown field bytes two levels deep must be detected")
		}
	})

	t.Run("nil element within a repeated message field is skipped, not a panic", func(t *testing.T) {
		req := &control.SolveRequest{
			Exporters: []*control.Exporter{nil},
		}
		if hasUnknownFields(req) {
			t.Fatal("a nil list element must not itself report unknown fields")
		}
	})
}
