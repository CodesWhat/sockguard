// Package buildkitproxy — this file carries Phase 3 (issue #185)'s strict
// unknown-field detector: hasUnknownFields walks a decoded message via
// google.golang.org/protobuf's reflection API to find protobuf unknown-field
// bytes anywhere in the message tree, per the #185 synthesis's divergence #3
// ("strict by default... unknown field in a known mediated message ->
// FailedPrecondition"). See bridge.go's forwardControlMediated for where
// this gates admission of a decoded SolveRequest/StatusRequest.
package buildkitproxy

import (
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// hasUnknownFields reports whether m, or any message reachable from m via a
// populated message- or group-typed field (a plain field, a list element, or
// a map value), carries protobuf unknown-field bytes — wire data present for
// a field number sockguard's vendored, pinned descriptor doesn't recognize.
// A future BuildKit/Buildx release that adds a new SolveRequest field would
// otherwise have that field silently ignored rather than reviewed; per the
// #185 synthesis this is grounds for outright denial
// (buildkit_schema_unsupported) instead.
//
// This walk does NOT reach inside solver/pb's Definition.Def: LLB's
// serialized Op graph is carried as opaque `repeated bytes`, not nested
// protobuf submessages (see solver/pb/ops.proto), so there is nothing for
// protobuf reflection to descend into there — a full LLB op-graph schema
// check would require a second, per-Op proto.Unmarshal pass this function
// does not attempt. See PROVENANCE.md and policy.go's SolvePolicy doc
// comment for that boundary.
func hasUnknownFields(m proto.Message) bool {
	if m == nil {
		return false
	}
	return messageHasUnknownFields(m.ProtoReflect())
}

// messageHasUnknownFields is hasUnknownFields' recursive worker, operating
// directly on protoreflect.Message so it can recurse into map values and
// list elements (which arrive as protoreflect.Message, not proto.Message)
// without a redundant interface round-trip at every level.
func messageHasUnknownFields(m protoreflect.Message) bool {
	if !m.IsValid() {
		return false
	}
	if len(m.GetUnknown()) > 0 {
		return true
	}

	found := false
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.IsMap():
			valueKind := fd.MapValue().Kind()
			if valueKind != protoreflect.MessageKind && valueKind != protoreflect.GroupKind {
				return true
			}
			v.Map().Range(func(_ protoreflect.MapKey, mv protoreflect.Value) bool {
				if messageHasUnknownFields(mv.Message()) {
					found = true
					return false
				}
				return true
			})
		case fd.IsList():
			if fd.Kind() != protoreflect.MessageKind && fd.Kind() != protoreflect.GroupKind {
				return true
			}
			list := v.List()
			for i := 0; i < list.Len() && !found; i++ {
				if messageHasUnknownFields(list.Get(i).Message()) {
					found = true
				}
			}
		case fd.Kind() == protoreflect.MessageKind || fd.Kind() == protoreflect.GroupKind:
			if messageHasUnknownFields(v.Message()) {
				found = true
			}
		}
		return !found
	})
	return found
}
