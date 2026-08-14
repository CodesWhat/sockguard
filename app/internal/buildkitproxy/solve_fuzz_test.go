package buildkitproxy

import (
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/codeswhat/sockguard/app/internal/buildkitproto/control"
	"github.com/codeswhat/sockguard/app/internal/buildkitproto/pb"
	"github.com/codeswhat/sockguard/app/internal/buildkitproto/sourcepolicy"
)

// solveMediationReasonCodes is the complete, low-cardinality vocabulary
// evaluateSolveRequest itself can ever return — see solve.go's own deny(...)
// call sites. buildkit_ref_not_owned, buildkit_method_denied,
// buildkit_message_too_large, buildkit_ref_limit_exceeded, and
// buildkit_internal_error are all real #185 audit reason codes too, but they
// are produced by bridge.go's forwardControlMediated/handleStream, never by
// evaluateSolveRequest in isolation — this fuzz target calls
// evaluateSolveRequest directly, so only its own four reasons are valid here.
var solveMediationReasonCodes = map[string]bool{
	"buildkit_protocol_error":     true,
	"buildkit_schema_unsupported": true,
	"buildkit_policy_denied":      true,
	"buildkit_invalid_ref":        true,
}

// solveMediationGRPCCodes mirrors solveMediationReasonCodes for the gRPC
// status codes solve.go's own deny(...) call sites use.
var solveMediationGRPCCodes = map[int]bool{
	grpcCodeInvalidArgument:    true,
	grpcCodePermissionDenied:   true,
	grpcCodeFailedPrecondition: true,
}

// statusMediationReasonCodes is evaluateStatusRequest's own (smaller)
// vocabulary — it only decodes and checks for unknown fields; ref-ownership
// (buildkit_ref_not_owned) is checked separately by bridge.go, using the
// SessionRegistry this decode-only function has no access to (see
// evaluateStatusRequest's own doc comment).
var statusMediationReasonCodes = map[string]bool{
	"buildkit_protocol_error":     true,
	"buildkit_schema_unsupported": true,
}

var statusMediationGRPCCodes = map[int]bool{
	grpcCodeInvalidArgument:    true,
	grpcCodeFailedPrecondition: true,
}

// fuzzSolvePolicies is a small, fixed set of SolvePolicy fixtures the fuzz
// target selects between (via a fuzzed index, not a fuzzed struct — Go's
// native fuzzer only mutates primitive-typed parameters) so mutation of the
// payload bytes gets exercised against meaningfully different policy
// postures: fully denied, minimally allowed, and fully permissive across
// every allowlist field evaluateSolveRequest's checks consult.
var fuzzSolvePolicies = []SolvePolicy{
	{}, // deny-everything default
	{Allow: true},
	{
		Allow:                     true,
		AllowHostNetwork:          true,
		AllowRemoteContext:        true,
		AllowedCacheImportTypes:   []string{"registry", "local", "gha"},
		AllowedCacheExportTypes:   []string{"registry", "local", "gha"},
		AllowedCacheRegistries:    []string{"example.com"},
		AllowedExporters:          []string{"image", "local", "oci"},
		AllowedExporterRegistries: []string{"example.com"},
	},
}

// mustMarshalFuzz is mustMarshal's *testing.F-seeding-time counterpart: every
// call site below marshals a well-formed, statically constructed message
// with no cyclic references, so proto.Marshal cannot fail in practice —
// panicking here (during f.Add registration, not inside f.Fuzz) surfaces a
// broken seed immediately rather than silently skipping it.
func mustMarshalFuzz(m proto.Message) []byte {
	b, err := proto.Marshal(m)
	if err != nil {
		panic("solve_fuzz_test: seed marshal failed: " + err.Error())
	}
	return b
}

// FuzzEvaluateSolveRequest fuzzes evaluateSolveRequest's protobuf decode and
// every policy-check branch it runs (checkSolveEntitlements/Frontend/Cache/
// Exporters/SourcePolicy/RemainingFields — see solve.go's own doc comment
// for the full field-by-field disposition). The seed corpus below is drawn
// from proto.Marshal outputs that each hit a distinct branch, mirroring
// TestEvaluateSolveRequest's table (solve_test.go) — deliberate structural
// coverage for the branches a byte-mutating fuzzer is unlikely to stumble
// into on its own (e.g. a specific known FrontendAttrs key, a recognized
// cache/exporter type string, an unknown-fields marker) — plus raw
// non-protobuf byte garbage for the decode-failure path, which pure mutation
// handles well on its own.
//
// Invariants (never panics is implicit — a panic fails the fuzz run):
//  1. Exactly one of (req, denial) is non-nil.
//  2. On denial, reasonCode is in solveMediationReasonCodes and code is in
//     solveMediationGRPCCodes — the low-cardinality vocabulary is never
//     exceeded, including under adversarial payload/policy combinations.
//  3. On admission (denial == nil), req is non-nil and req.GetRef() != ""
//     (evaluateSolveRequest's own last check rejects an empty ref before
//     ever returning success).
func FuzzEvaluateSolveRequest(f *testing.F) {
	seeds := []proto.Message{
		&control.SolveRequest{},         // empty ref -> buildkit_invalid_ref
		&control.SolveRequest{Ref: "r"}, // minimal admit
		&control.SolveRequest{Ref: "r", Entitlements: []string{"security.insecure"}}, // always denied
		&control.SolveRequest{Ref: "r", Entitlements: []string{"network.host"}},
		&control.SolveRequest{Entitlements: []string{"network.host"}}, // no ref, deny path taken first for entitlement
		&control.SolveRequest{Ref: "r", Entitlements: []string{"some.future.entitlement"}},
		&control.SolveRequest{Ref: "r", Frontend: "gateway.v0"},
		&control.SolveRequest{Ref: "r", Frontend: "dockerfile.v0"},
		&control.SolveRequest{Ref: "r", Frontend: "dockerfile.v0", FrontendAttrs: map[string]string{"some-future-attr": "x"}},
		&control.SolveRequest{Ref: "r", Frontend: "dockerfile.v0", FrontendAttrs: map[string]string{"dockerfilekey": "forbidden"}}, // known default-deny attr, not in knownFrontendAttrKeys
		&control.SolveRequest{Ref: "r", Frontend: "dockerfile.v0", FrontendAttrs: map[string]string{"build-arg:FOO": "bar"}},
		&control.SolveRequest{Ref: "r", Frontend: "dockerfile.v0", FrontendAttrs: map[string]string{"context": "https://example.com/repo.git"}},
		&control.SolveRequest{Ref: "r", Frontend: "dockerfile.v0", FrontendAttrs: map[string]string{"context": "."}},
		&control.SolveRequest{Ref: "r", Frontend: "dockerfile.v0", FrontendAttrs: map[string]string{"force-network-mode": "host"}},
		&control.SolveRequest{Ref: "r", Frontend: "dockerfile.v0", FrontendAttrs: map[string]string{"force-network-mode": "none"}},
		&control.SolveRequest{Ref: "r", ExporterDeprecated: "image"},
		&control.SolveRequest{Ref: "r", ExporterAttrsDeprecated: map[string]string{"push": "true"}},
		&control.SolveRequest{Ref: "r", Cache: &control.CacheOptions{ExportRefDeprecated: "example.com/cache"}},
		&control.SolveRequest{Ref: "r", Cache: &control.CacheOptions{ImportRefsDeprecated: []string{"example.com/cache"}}},
		&control.SolveRequest{Ref: "r", Cache: &control.CacheOptions{ExportAttrsDeprecated: map[string]string{"mode": "max"}}},
		&control.SolveRequest{Ref: "r", Cache: &control.CacheOptions{Imports: []*control.CacheOptionsEntry{{Type: "gha"}}}},
		&control.SolveRequest{Ref: "r", Cache: &control.CacheOptions{Imports: []*control.CacheOptionsEntry{{Type: "registry", Attrs: map[string]string{"ref": "example.com/cache"}}}}},
		&control.SolveRequest{Ref: "r", Cache: &control.CacheOptions{Imports: []*control.CacheOptionsEntry{{Type: "registry", Attrs: map[string]string{"ref": "evil.example/cache"}}}}},
		&control.SolveRequest{Ref: "r", Cache: &control.CacheOptions{Exports: []*control.CacheOptionsEntry{{Type: "registry", Attrs: map[string]string{"ref": "example.com/cache"}}}}},
		&control.SolveRequest{Ref: "r", Exporters: []*control.Exporter{{Type: "oci"}}},
		&control.SolveRequest{Ref: "r", Exporters: []*control.Exporter{{Type: "image", Attrs: map[string]string{"push": "true", "name": "example.com/img"}}}},
		&control.SolveRequest{Ref: "r", Exporters: []*control.Exporter{{Type: "image", Attrs: map[string]string{"push": "true", "name": "evil.example/img"}}}},
		&control.SolveRequest{Ref: "r", Exporters: []*control.Exporter{{Type: "image", Attrs: map[string]string{"push": "1", "name": "evil.example/img"}}}},
		&control.SolveRequest{Ref: "r", Exporters: []*control.Exporter{{Type: "image", Attrs: map[string]string{"push": "sometimes", "name": "example.com/img"}}}},
		&control.SolveRequest{Ref: "r", Exporters: []*control.Exporter{{Type: "image", Attrs: map[string]string{"push": "true", "name": "example.com/a,evil.example/b"}}}},
		&control.SolveRequest{Ref: "r", Exporters: []*control.Exporter{{Type: "image", Attrs: map[string]string{"push": "true"}}}},
		&control.SolveRequest{Ref: "r", EnableSessionExporter: true},
		&control.SolveRequest{Ref: "r", SourcePolicy: &sourcepolicy.Policy{Rules: []*sourcepolicy.Rule{{}}}},
		&control.SolveRequest{Ref: "r", SourcePolicy: &sourcepolicy.Policy{Version: 1}},
		&control.SolveRequest{Ref: "r", SourcePolicySession: "some-session-id"},
		&control.SolveRequest{Ref: "r", FrontendInputs: map[string]*pb.Definition{"context": nil}},
		&control.SolveRequest{Ref: "r", ProxyNetwork: true},
		&control.SolveRequest{Ref: "r", CompatibilityVersion: 3},
		&control.SolveRequest{Ref: "r", Internal: true},
		&control.SolveRequest{Ref: "r", Session: "some-buildkit-session-uuid"},
	}

	for _, idx := range []uint8{0, 1, 2} {
		for _, m := range seeds {
			f.Add(mustMarshalFuzz(m), idx)
		}
	}

	unknownFieldsReq := &control.SolveRequest{Ref: "r"}
	unknownFieldsReq.ProtoReflect().SetUnknown(unknownFieldBytes())
	f.Add(mustMarshalFuzz(unknownFieldsReq), uint8(2))

	f.Add(malformedPayload, uint8(2))
	f.Add([]byte{}, uint8(0))
	f.Add([]byte("not a protobuf message at all"), uint8(2))
	f.Add([]byte{0x08}, uint8(1)) // truncated varint tag

	f.Fuzz(func(t *testing.T, payload []byte, policyIdx uint8) {
		policy := fuzzSolvePolicies[int(policyIdx)%len(fuzzSolvePolicies)]
		req, denial := evaluateSolveRequest(payload, Policy{Control: ControlPolicy{Solve: policy}})

		if denial != nil {
			if req != nil {
				t.Fatalf("denial %+v returned alongside a non-nil req %+v", denial, req)
			}
			if !solveMediationReasonCodes[denial.reasonCode] {
				t.Fatalf("denial reasonCode %q is outside evaluateSolveRequest's known vocabulary", denial.reasonCode)
			}
			if !solveMediationGRPCCodes[denial.code] {
				t.Fatalf("denial code %d is outside evaluateSolveRequest's known gRPC code set", denial.code)
			}
			return
		}
		if req == nil {
			t.Fatal("nil denial but req is also nil — evaluateSolveRequest must always return exactly one non-nil")
		}
		if req.GetRef() == "" {
			t.Fatal("admitted request has an empty Ref — evaluateSolveRequest's own last check must have rejected this")
		}
	})
}

// FuzzEvaluateStatusRequest fuzzes evaluateStatusRequest's protobuf decode
// and unknown-fields check. See evaluateStatusRequest's own doc comment for
// why ref-ownership is deliberately out of scope here — it needs the
// bridge's SessionRegistry, which this decode-only function never touches.
func FuzzEvaluateStatusRequest(f *testing.F) {
	f.Add(mustMarshalFuzz(&control.StatusRequest{}))
	f.Add(mustMarshalFuzz(&control.StatusRequest{Ref: "build-ref-1"}))
	f.Add(mustMarshalFuzz(&control.StatusRequest{Ref: ""}))

	unknownFieldsReq := &control.StatusRequest{Ref: "r"}
	unknownFieldsReq.ProtoReflect().SetUnknown(unknownFieldBytes())
	f.Add(mustMarshalFuzz(unknownFieldsReq))

	f.Add(malformedPayload)
	f.Add([]byte{})
	f.Add([]byte("not a protobuf message at all"))
	f.Add([]byte{0x08})

	f.Fuzz(func(t *testing.T, payload []byte) {
		req, denial := evaluateStatusRequest(payload)

		if denial != nil {
			if req != nil {
				t.Fatalf("denial %+v returned alongside a non-nil req %+v", denial, req)
			}
			if !statusMediationReasonCodes[denial.reasonCode] {
				t.Fatalf("denial reasonCode %q is outside evaluateStatusRequest's known vocabulary", denial.reasonCode)
			}
			if !statusMediationGRPCCodes[denial.code] {
				t.Fatalf("denial code %d is outside evaluateStatusRequest's known gRPC code set", denial.code)
			}
			return
		}
		if req == nil {
			t.Fatal("nil denial but req is also nil — evaluateStatusRequest must always return exactly one non-nil")
		}
	})
}
