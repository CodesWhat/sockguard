package buildkitproxy

import (
	"strconv"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/codeswhat/sockguard/v3/app/internal/buildkitproto/gateway"
	"github.com/codeswhat/sockguard/v3/app/internal/buildkitproto/pb"
	"github.com/codeswhat/sockguard/v3/app/internal/buildkitproto/sourcepolicy"
)

// TestGatewayRequestMediationDenials drives every frontend-gateway deny branch
// that the broader TestGatewayRequestPolicy table does not reach. Each case
// must come back as a permission-denied buildkit_policy_denied with the
// branch-specific message, so an earlier check cannot mask the one under test.
func TestGatewayRequestMediationDenials(t *testing.T) {
	t.Parallel()

	nestedBuild := &pb.Definition{Def: [][]byte{
		mustMarshal(t, &pb.Op{Op: &pb.Op_Build{Build: &pb.BuildOp{}}}),
	}}
	// Run instructions are enabled so the earlier "operation is not approved"
	// check passes and the dedicated nested-build deny is the one that fires.
	runPolicy := allowAllPolicy
	runPolicy.Control.Solve.AllowRunInstructions = true

	overLimitRefs := make(map[string]*gateway.Ref)
	overLimitDeprecated := make(map[string]string)
	for i := 0; i <= maxGatewaySolvesPerBuild; i++ {
		key := "k" + strconv.Itoa(i)
		overLimitRefs[key] = &gateway.Ref{Id: "result"}
		overLimitDeprecated[key] = "result"
	}

	returnOf := func(result *gateway.Result) *gateway.ReturnRequest {
		return &gateway.ReturnRequest{Result: result}
	}
	policyWithCache := func(types, registries []string) Policy {
		p := allowAllPolicy
		p.Control.Solve.AllowedCacheImportTypes = types
		p.Control.Solve.AllowedCacheRegistries = registries
		return p
	}

	for _, tc := range []struct {
		name    string
		method  string
		request proto.Message
		policy  Policy
		message string
	}{
		{
			name:    "nested_build_run_allowed",
			method:  "Solve",
			request: &gateway.SolveRequest{Definition: nestedBuild},
			policy:  runPolicy,
			message: "nested daemon-resolved builds are not mediated by the frontend gateway",
		},
		{
			name:    "return_refs_invalid_id",
			method:  "Return",
			request: returnOf(&gateway.Result{Result: &gateway.Result_Refs{Refs: &gateway.RefMap{Refs: map[string]*gateway.Ref{"a": {Id: "bad\nref"}}}}}),
			policy:  allowAllPolicy,
			message: "invalid frontend result ref",
		},
		{
			name:    "return_refs_over_limit",
			method:  "Return",
			request: returnOf(&gateway.Result{Result: &gateway.Result_Refs{Refs: &gateway.RefMap{Refs: overLimitRefs}}}),
			policy:  allowAllPolicy,
			message: "too many frontend result refs",
		},
		{
			name:    "return_ref_deprecated_invalid_id",
			method:  "Return",
			request: returnOf(&gateway.Result{Result: &gateway.Result_RefDeprecated{RefDeprecated: "bad\nref"}}),
			policy:  allowAllPolicy,
			message: "invalid frontend result ref",
		},
		{
			name:    "return_refs_deprecated_invalid_id",
			method:  "Return",
			request: returnOf(&gateway.Result{Result: &gateway.Result_RefsDeprecated{RefsDeprecated: &gateway.RefMapDeprecated{Refs: map[string]string{"a": "bad\nref"}}}}),
			policy:  allowAllPolicy,
			message: "invalid frontend result ref",
		},
		{
			name:    "return_refs_deprecated_over_limit",
			method:  "Return",
			request: returnOf(&gateway.Result{Result: &gateway.Result_RefsDeprecated{RefsDeprecated: &gateway.RefMapDeprecated{Refs: overLimitDeprecated}}}),
			policy:  allowAllPolicy,
			message: "too many frontend result refs",
		},
		{
			name:   "cache_import_ungranted_type",
			method: "Solve",
			request: &gateway.SolveRequest{CacheImports: []*gateway.CacheOptionsEntry{
				{Type: "local", Attrs: map[string]string{"src": "/tmp"}},
			}},
			policy:  policyWithCache([]string{"registry"}, []string{"registry.example.com"}),
			message: "cache type is not permitted",
		},
		{
			name:   "cache_import_ungranted_registry",
			method: "Solve",
			request: &gateway.SolveRequest{CacheImports: []*gateway.CacheOptionsEntry{
				{Type: "registry", Attrs: map[string]string{"ref": "evil.example.net/cache:latest"}},
			}},
			policy:  policyWithCache([]string{"registry"}, []string{"registry.example.com"}),
			message: "cache registry is not permitted",
		},
		{
			name:    "source_policies",
			method:  "Solve",
			request: &gateway.SolveRequest{SourcePolicies: []*sourcepolicy.Policy{{Version: 1}}},
			policy:  allowAllPolicy,
			message: "frontend solve contains an unmediated delegation or output",
		},
		{
			name:   "attestation_chain",
			method: "ResolveSourceMeta",
			request: &gateway.ResolveSourceMetaRequest{
				Source: &pb.SourceOp{Identifier: "docker-image://busybox"},
				Image:  &gateway.ResolveSourceImageRequest{AttestationChain: true},
			},
			policy:  allowAllPolicy,
			message: "source policy and attestation resolution are not mediated",
		},
		{
			name:   "resolve_attestations",
			method: "ResolveSourceMeta",
			request: &gateway.ResolveSourceMetaRequest{
				Source: &pb.SourceOp{Identifier: "docker-image://busybox"},
				Image:  &gateway.ResolveSourceImageRequest{ResolveAttestations: []string{"https://slsa.dev/provenance/v0.2"}},
			},
			policy:  allowAllPolicy,
			message: "source policy and attestation resolution are not mediated",
		},
		{
			name:   "return_attestations",
			method: "Return",
			request: returnOf(&gateway.Result{
				Result:       &gateway.Result_Ref{Ref: &gateway.Ref{Id: "result"}},
				Attestations: map[string]*gateway.Attestations{"linux/amd64": {}},
			}),
			policy:  allowAllPolicy,
			message: "frontend attestations are not mediated",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := evaluateGatewayRequest(tc.method, mustMarshal(t, tc.request), tc.policy)
			if d == nil {
				t.Fatal("request was admitted, want denial")
			}
			if d.code != grpcCodePermissionDenied || d.reasonCode != "buildkit_policy_denied" {
				t.Fatalf("denial = code %d reason %q, want permission denied buildkit_policy_denied", d.code, d.reasonCode)
			}
			if d.message != tc.message {
				t.Fatalf("denial message = %q, want %q", d.message, tc.message)
			}
		})
	}
}
