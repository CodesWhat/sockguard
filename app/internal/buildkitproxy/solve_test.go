package buildkitproxy

import (
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/codeswhat/sockguard/app/internal/buildkitproto/control"
	"github.com/codeswhat/sockguard/app/internal/buildkitproto/pb"
	"github.com/codeswhat/sockguard/app/internal/buildkitproto/sourcepolicy"
)

// malformedPayload is a truncated protobuf varint tag: enough to fail
// proto.Unmarshal with an error rather than decoding to a zero-value
// message.
var malformedPayload = []byte{0x08}

func mustMarshal(t testing.TB, m proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func denyReason(d *mediationDenial) string {
	if d == nil {
		return ""
	}
	return d.reasonCode
}

func TestEvaluateSolveRequest(t *testing.T) {
	fullyAllowed := SolvePolicy{
		Allow:                     true,
		AllowHostNetwork:          true,
		AllowRemoteContext:        true,
		AllowedCacheImportTypes:   []string{"registry", "local"},
		AllowedCacheExportTypes:   []string{"registry", "local"},
		AllowedCacheRegistries:    []string{"example.com"},
		AllowedExporters:          []string{"image", "local"},
		AllowedExporterRegistries: []string{"example.com"},
	}

	cases := []struct {
		name       string
		payload    []byte
		policy     SolvePolicy
		wantDenied bool
		wantReason string
		wantCode   int
	}{
		{
			name:       "malformed payload",
			payload:    malformedPayload,
			policy:     fullyAllowed,
			wantDenied: true,
			wantReason: "buildkit_protocol_error",
			wantCode:   grpcCodeInvalidArgument,
		},
		{
			name: "unknown fields anywhere in the message",
			payload: func() []byte {
				req := &control.SolveRequest{}
				req.ProtoReflect().SetUnknown(unknownFieldBytes())
				return mustMarshal(t, req)
			}(),
			policy:     fullyAllowed,
			wantDenied: true,
			wantReason: "buildkit_schema_unsupported",
			wantCode:   grpcCodeFailedPrecondition,
		},
		{
			name:       "security.insecure entitlement is always denied",
			payload:    mustMarshal(t, &control.SolveRequest{Entitlements: []string{"security.insecure"}}),
			policy:     fullyAllowed,
			wantDenied: true,
			wantReason: "buildkit_policy_denied",
			wantCode:   grpcCodePermissionDenied,
		},
		{
			name:       "network.host entitlement without allow_host_network",
			payload:    mustMarshal(t, &control.SolveRequest{Entitlements: []string{"network.host"}}),
			policy:     SolvePolicy{Allow: true},
			wantDenied: true,
			wantReason: "buildkit_policy_denied",
			wantCode:   grpcCodePermissionDenied,
		},
		{
			name:       "network.host entitlement with allow_host_network",
			payload:    mustMarshal(t, &control.SolveRequest{Ref: "r", Entitlements: []string{"network.host"}}),
			policy:     SolvePolicy{Allow: true, AllowHostNetwork: true},
			wantDenied: false,
		},
		{
			name:       "unrecognized entitlement",
			payload:    mustMarshal(t, &control.SolveRequest{Entitlements: []string{"some.future.entitlement"}}),
			policy:     fullyAllowed,
			wantDenied: true,
			wantReason: "buildkit_policy_denied",
			wantCode:   grpcCodePermissionDenied,
		},
		{
			name:       "frontend not on the allowlist",
			payload:    mustMarshal(t, &control.SolveRequest{Frontend: "gateway.v0"}),
			policy:     fullyAllowed,
			wantDenied: true,
			wantReason: "buildkit_policy_denied",
			wantCode:   grpcCodePermissionDenied,
		},
		{
			name:       "empty frontend (raw LLB) is allowed",
			payload:    mustMarshal(t, &control.SolveRequest{Ref: "r", Frontend: ""}),
			policy:     fullyAllowed,
			wantDenied: false,
		},
		{
			name:       "dockerfile.v0 frontend is allowed",
			payload:    mustMarshal(t, &control.SolveRequest{Ref: "r", Frontend: "dockerfile.v0"}),
			policy:     fullyAllowed,
			wantDenied: false,
		},
		{
			name: "raw LLB definition with an ExecOp is denied while RUN instructions are restricted",
			payload: mustMarshal(t, &control.SolveRequest{
				Ref:      "r",
				Frontend: "",
				Definition: &pb.Definition{
					Def: [][]byte{mustMarshal(t, &pb.Op{Op: &pb.Op_Exec{Exec: &pb.ExecOp{}}})},
				},
			}),
			policy:     fullyAllowed,
			wantDenied: true,
			wantReason: "buildkit_policy_denied",
			wantCode:   grpcCodePermissionDenied,
		},
		{
			name: "raw LLB definition with an ExecOp is admitted with allow_run_instructions",
			payload: mustMarshal(t, &control.SolveRequest{
				Ref:      "r",
				Frontend: "",
				Definition: &pb.Definition{
					Def: [][]byte{mustMarshal(t, &pb.Op{Op: &pb.Op_Exec{Exec: &pb.ExecOp{}}})},
				},
			}),
			policy: SolvePolicy{
				Allow:                fullyAllowed.Allow,
				AllowHostNetwork:     fullyAllowed.AllowHostNetwork,
				AllowRemoteContext:   fullyAllowed.AllowRemoteContext,
				AllowRunInstructions: true,
			},
			wantDenied: false,
		},
		{
			name: "raw LLB definition without an ExecOp is admitted while RUN instructions are restricted",
			payload: mustMarshal(t, &control.SolveRequest{
				Ref:      "r",
				Frontend: "",
				Definition: &pb.Definition{
					Def: [][]byte{mustMarshal(t, &pb.Op{Op: &pb.Op_Source{Source: &pb.SourceOp{Identifier: "docker-image://busybox"}}})},
				},
			}),
			policy:     fullyAllowed,
			wantDenied: false,
		},
		{
			name: "raw LLB definition with an undecodable op is denied while RUN instructions are restricted",
			payload: mustMarshal(t, &control.SolveRequest{
				Ref:      "r",
				Frontend: "",
				Definition: &pb.Definition{
					Def: [][]byte{malformedPayload},
				},
			}),
			policy:     fullyAllowed,
			wantDenied: true,
			wantReason: "buildkit_policy_denied",
			wantCode:   grpcCodePermissionDenied,
		},
		{
			name: "raw LLB definition with an ExecOp nested inside a BuildOp is denied while RUN instructions are restricted",
			payload: mustMarshal(t, &control.SolveRequest{
				Ref:      "r",
				Frontend: "",
				Definition: &pb.Definition{
					Def: [][]byte{mustMarshal(t, &pb.Op{Op: &pb.Op_Build{Build: &pb.BuildOp{
						Def: &pb.Definition{
							Def: [][]byte{mustMarshal(t, &pb.Op{Op: &pb.Op_Exec{Exec: &pb.ExecOp{}}})},
						},
					}}})},
				},
			}),
			policy:     fullyAllowed,
			wantDenied: true,
			wantReason: "buildkit_policy_denied",
			wantCode:   grpcCodePermissionDenied,
		},
		{
			name: "unknown FrontendAttrs key",
			payload: mustMarshal(t, &control.SolveRequest{
				Frontend:      "dockerfile.v0",
				FrontendAttrs: map[string]string{"some-future-attr": "x"},
			}),
			policy:     fullyAllowed,
			wantDenied: true,
			wantReason: "buildkit_schema_unsupported",
			wantCode:   grpcCodeFailedPrecondition,
		},
		{
			name: "known build-arg: prefix family attr key",
			payload: mustMarshal(t, &control.SolveRequest{
				Ref:           "r",
				Frontend:      "dockerfile.v0",
				FrontendAttrs: map[string]string{"build-arg:FOO": "bar"},
			}),
			policy:     fullyAllowed,
			wantDenied: false,
		},
		{
			name: "remote build context without allow_remote_context",
			payload: mustMarshal(t, &control.SolveRequest{
				Frontend:      "dockerfile.v0",
				FrontendAttrs: map[string]string{"context": "https://example.com/repo.git"},
			}),
			policy:     SolvePolicy{Allow: true},
			wantDenied: true,
			wantReason: "buildkit_policy_denied",
			wantCode:   grpcCodePermissionDenied,
		},
		{
			name: "remote build context with allow_remote_context and allow_run_instructions",
			payload: mustMarshal(t, &control.SolveRequest{
				Ref:           "r",
				Frontend:      "dockerfile.v0",
				FrontendAttrs: map[string]string{"context": "https://example.com/repo.git"},
			}),
			policy:     SolvePolicy{Allow: true, AllowRemoteContext: true, AllowRunInstructions: true},
			wantDenied: false,
		},
		{
			name: "remote build context denied when RUN instructions are restricted",
			payload: mustMarshal(t, &control.SolveRequest{
				Frontend:      "dockerfile.v0",
				FrontendAttrs: map[string]string{"context": "https://example.com/repo.git"},
			}),
			// allow_remote_context alone is not enough: buildkitd fetches the
			// Dockerfile from the remote URL itself, so it never reaches
			// hold-and-inspect — mirror classic /build and deny.
			policy:     SolvePolicy{Allow: true, AllowRemoteContext: true},
			wantDenied: true,
			wantReason: "buildkit_policy_denied",
			wantCode:   grpcCodePermissionDenied,
		},
		{
			name: "upload-session context still requires allow_run_instructions",
			payload: mustMarshal(t, &control.SolveRequest{
				Ref:           "r",
				Frontend:      "dockerfile.v0",
				FrontendAttrs: map[string]string{"context": "http://buildkit-session/abc123"},
			}),
			// A buildkit-session upload context can have its Dockerfile
			// resolved directly from the same fetched context archive by
			// BuildKit's dockerui frontend, bypassing the "dockerfile"-named
			// FileSync/DiffCopy stream filesync.go inspects — so it gets no
			// exemption from the RUN-restriction gate any other remote-shaped
			// context is subject to.
			policy:     SolvePolicy{Allow: true, AllowRemoteContext: true},
			wantDenied: true,
			wantReason: "buildkit_policy_denied",
			wantCode:   grpcCodePermissionDenied,
		},
		{
			name: "upload-session context is admitted with allow_run_instructions",
			payload: mustMarshal(t, &control.SolveRequest{
				Ref:           "r",
				Frontend:      "dockerfile.v0",
				FrontendAttrs: map[string]string{"context": "http://buildkit-session/abc123"},
			}),
			policy:     SolvePolicy{Allow: true, AllowRemoteContext: true, AllowRunInstructions: true},
			wantDenied: false,
		},
		{
			name: "local build context needs no allow_remote_context",
			payload: mustMarshal(t, &control.SolveRequest{
				Ref:           "r",
				Frontend:      "dockerfile.v0",
				FrontendAttrs: map[string]string{"context": "."},
			}),
			policy:     SolvePolicy{Allow: true},
			wantDenied: false,
		},
		{
			name: "force-network-mode host without allow_host_network",
			payload: mustMarshal(t, &control.SolveRequest{
				Frontend:      "dockerfile.v0",
				FrontendAttrs: map[string]string{"force-network-mode": "host"},
			}),
			policy:     SolvePolicy{Allow: true},
			wantDenied: true,
			wantReason: "buildkit_policy_denied",
			wantCode:   grpcCodePermissionDenied,
		},
		{
			name: "force-network-mode host with allow_host_network",
			payload: mustMarshal(t, &control.SolveRequest{
				Ref:           "r",
				Frontend:      "dockerfile.v0",
				FrontendAttrs: map[string]string{"force-network-mode": "host"},
			}),
			policy:     SolvePolicy{Allow: true, AllowHostNetwork: true},
			wantDenied: false,
		},
		{
			name: "force-network-mode non-host value needs no allowance",
			payload: mustMarshal(t, &control.SolveRequest{
				Ref:           "r",
				Frontend:      "dockerfile.v0",
				FrontendAttrs: map[string]string{"force-network-mode": "none"},
			}),
			policy:     SolvePolicy{Allow: true},
			wantDenied: false,
		},
		{
			name:       "deprecated top-level ExporterDeprecated is denied outright",
			payload:    mustMarshal(t, &control.SolveRequest{ExporterDeprecated: "image"}),
			policy:     fullyAllowed,
			wantDenied: true,
			wantReason: "buildkit_schema_unsupported",
			wantCode:   grpcCodeFailedPrecondition,
		},
		{
			name:       "deprecated top-level ExporterAttrsDeprecated is denied outright",
			payload:    mustMarshal(t, &control.SolveRequest{ExporterAttrsDeprecated: map[string]string{"push": "true"}}),
			policy:     fullyAllowed,
			wantDenied: true,
			wantReason: "buildkit_schema_unsupported",
			wantCode:   grpcCodeFailedPrecondition,
		},
		{
			name: "deprecated CacheOptions.ExportRefDeprecated is denied outright",
			payload: mustMarshal(t, &control.SolveRequest{
				Cache: &control.CacheOptions{ExportRefDeprecated: "example.com/cache"},
			}),
			policy:     fullyAllowed,
			wantDenied: true,
			wantReason: "buildkit_schema_unsupported",
			wantCode:   grpcCodeFailedPrecondition,
		},
		{
			name: "deprecated CacheOptions.ImportRefsDeprecated is denied outright",
			payload: mustMarshal(t, &control.SolveRequest{
				Cache: &control.CacheOptions{ImportRefsDeprecated: []string{"example.com/cache"}},
			}),
			policy:     fullyAllowed,
			wantDenied: true,
			wantReason: "buildkit_schema_unsupported",
			wantCode:   grpcCodeFailedPrecondition,
		},
		{
			name: "deprecated CacheOptions.ExportAttrsDeprecated is denied outright",
			payload: mustMarshal(t, &control.SolveRequest{
				Cache: &control.CacheOptions{ExportAttrsDeprecated: map[string]string{"mode": "max"}},
			}),
			policy:     fullyAllowed,
			wantDenied: true,
			wantReason: "buildkit_schema_unsupported",
			wantCode:   grpcCodeFailedPrecondition,
		},
		{
			name: "nil Cache is a no-op",
			payload: mustMarshal(t, &control.SolveRequest{
				Ref:   "r",
				Cache: nil,
			}),
			policy:     fullyAllowed,
			wantDenied: false,
		},
		{
			name: "cache import type not on the allowlist",
			payload: mustMarshal(t, &control.SolveRequest{
				Cache: &control.CacheOptions{
					Imports: []*control.CacheOptionsEntry{{Type: "gha"}},
				},
			}),
			policy:     SolvePolicy{Allow: true, AllowedCacheImportTypes: []string{"registry"}},
			wantDenied: true,
			wantReason: "buildkit_policy_denied",
			wantCode:   grpcCodePermissionDenied,
		},
		{
			name: "cache import registry type not on the registry allowlist",
			payload: mustMarshal(t, &control.SolveRequest{
				Cache: &control.CacheOptions{
					Imports: []*control.CacheOptionsEntry{{Type: "registry", Attrs: map[string]string{"ref": "evil.example/cache"}}},
				},
			}),
			policy: SolvePolicy{
				Allow:                   true,
				AllowedCacheImportTypes: []string{"registry"},
				AllowedCacheRegistries:  []string{"example.com"},
			},
			wantDenied: true,
			wantReason: "buildkit_policy_denied",
			wantCode:   grpcCodePermissionDenied,
		},
		{
			name: "cache import registry type on the registry allowlist",
			payload: mustMarshal(t, &control.SolveRequest{
				Ref: "r",
				Cache: &control.CacheOptions{
					Imports: []*control.CacheOptionsEntry{{Type: "registry", Attrs: map[string]string{"ref": "example.com/cache"}}},
				},
			}),
			policy: SolvePolicy{
				Allow:                   true,
				AllowedCacheImportTypes: []string{"registry"},
				AllowedCacheRegistries:  []string{"example.com"},
			},
			wantDenied: false,
		},
		{
			name: "cache import non-registry type needs no registry allowance",
			payload: mustMarshal(t, &control.SolveRequest{
				Ref: "r",
				Cache: &control.CacheOptions{
					Imports: []*control.CacheOptionsEntry{{Type: "local"}},
				},
			}),
			policy:     SolvePolicy{Allow: true, AllowedCacheImportTypes: []string{"local"}},
			wantDenied: false,
		},
		{
			name: "cache export type not on the allowlist",
			payload: mustMarshal(t, &control.SolveRequest{
				Cache: &control.CacheOptions{
					Exports: []*control.CacheOptionsEntry{{Type: "s3"}},
				},
			}),
			policy:     SolvePolicy{Allow: true, AllowedCacheExportTypes: []string{"registry"}},
			wantDenied: true,
			wantReason: "buildkit_policy_denied",
			wantCode:   grpcCodePermissionDenied,
		},
		{
			name: "cache export registry type on the registry allowlist",
			payload: mustMarshal(t, &control.SolveRequest{
				Ref: "r",
				Cache: &control.CacheOptions{
					Exports: []*control.CacheOptionsEntry{{Type: "registry", Attrs: map[string]string{"ref": "example.com/cache"}}},
				},
			}),
			policy: SolvePolicy{
				Allow:                   true,
				AllowedCacheExportTypes: []string{"registry"},
				AllowedCacheRegistries:  []string{"example.com"},
			},
			wantDenied: false,
		},
		{
			name:       "exporter type not on the allowlist",
			payload:    mustMarshal(t, &control.SolveRequest{Exporters: []*control.Exporter{{Type: "oci"}}}),
			policy:     SolvePolicy{Allow: true, AllowedExporters: []string{"image"}},
			wantDenied: true,
			wantReason: "buildkit_policy_denied",
			wantCode:   grpcCodePermissionDenied,
		},
		{
			name: "image exporter push to a registry not on the allowlist",
			payload: mustMarshal(t, &control.SolveRequest{
				Exporters: []*control.Exporter{{
					Type:  "image",
					Attrs: map[string]string{"push": "true", "name": "evil.example/img"},
				}},
			}),
			policy: SolvePolicy{
				Allow:                     true,
				AllowedExporters:          []string{"image"},
				AllowedExporterRegistries: []string{"example.com"},
			},
			wantDenied: true,
			wantReason: "buildkit_policy_denied",
			wantCode:   grpcCodePermissionDenied,
		},
		{
			name: "image exporter push to an allowed registry",
			payload: mustMarshal(t, &control.SolveRequest{
				Ref: "r",
				Exporters: []*control.Exporter{{
					Type:  "image",
					Attrs: map[string]string{"push": "true", "name": "example.com/img"},
				}},
			}),
			policy: SolvePolicy{
				Allow:                     true,
				AllowedExporters:          []string{"image"},
				AllowedExporterRegistries: []string{"example.com"},
			},
			wantDenied: false,
		},
		{
			name: "image exporter without push needs no registry allowance",
			payload: mustMarshal(t, &control.SolveRequest{
				Ref: "r",
				Exporters: []*control.Exporter{{
					Type:  "image",
					Attrs: map[string]string{"push": "false", "name": "evil.example/img"},
				}},
			}),
			policy:     SolvePolicy{Allow: true, AllowedExporters: []string{"image"}},
			wantDenied: false,
		},
		{
			name:       "EnableSessionExporter is always denied",
			payload:    mustMarshal(t, &control.SolveRequest{EnableSessionExporter: true}),
			policy:     fullyAllowed,
			wantDenied: true,
			wantReason: "buildkit_policy_denied",
			wantCode:   grpcCodePermissionDenied,
		},
		{
			name: "non-empty source policy rules are always denied",
			payload: mustMarshal(t, &control.SolveRequest{
				SourcePolicy: &sourcepolicy.Policy{Rules: []*sourcepolicy.Rule{{}}},
			}),
			policy:     fullyAllowed,
			wantDenied: true,
			wantReason: "buildkit_policy_denied",
			wantCode:   grpcCodePermissionDenied,
		},
		{
			name: "source policy with no rules is a no-op",
			payload: mustMarshal(t, &control.SolveRequest{
				Ref:          "r",
				SourcePolicy: &sourcepolicy.Policy{Version: 1},
			}),
			policy:     fullyAllowed,
			wantDenied: false,
		},
		{
			name:       "fully permitted request admits and returns the decoded ref",
			payload:    mustMarshal(t, &control.SolveRequest{Ref: "build-ref-1", Frontend: "dockerfile.v0"}),
			policy:     fullyAllowed,
			wantDenied: false,
		},
		{
			name:       "empty ref is denied even when otherwise fully permitted",
			payload:    mustMarshal(t, &control.SolveRequest{}),
			policy:     fullyAllowed,
			wantDenied: true,
			wantReason: "buildkit_invalid_ref",
			wantCode:   grpcCodeInvalidArgument,
		},
		{
			name: "non-empty SourcePolicySession is always denied",
			payload: mustMarshal(t, &control.SolveRequest{
				Ref:                 "r",
				SourcePolicySession: "some-session-id",
			}),
			policy:     fullyAllowed,
			wantDenied: true,
			wantReason: "buildkit_policy_denied",
			wantCode:   grpcCodePermissionDenied,
		},
		{
			name: "non-empty FrontendInputs is always denied",
			payload: mustMarshal(t, &control.SolveRequest{
				Ref:            "r",
				FrontendInputs: map[string]*pb.Definition{"context": nil},
			}),
			policy:     fullyAllowed,
			wantDenied: true,
			wantReason: "buildkit_policy_denied",
			wantCode:   grpcCodePermissionDenied,
		},
		{
			name: "ProxyNetwork is always denied",
			payload: mustMarshal(t, &control.SolveRequest{
				Ref:          "r",
				ProxyNetwork: true,
			}),
			policy:     fullyAllowed,
			wantDenied: true,
			wantReason: "buildkit_policy_denied",
			wantCode:   grpcCodePermissionDenied,
		},
		{
			name: "CompatibilityVersion is forwarded unexamined",
			payload: mustMarshal(t, &control.SolveRequest{
				Ref:                  "r",
				CompatibilityVersion: 3,
			}),
			policy:     fullyAllowed,
			wantDenied: false,
		},
		{
			name: "Internal is forwarded unexamined",
			payload: mustMarshal(t, &control.SolveRequest{
				Ref:      "r",
				Internal: true,
			}),
			policy:     fullyAllowed,
			wantDenied: false,
		},
		{
			name: "Session is forwarded unexamined",
			payload: mustMarshal(t, &control.SolveRequest{
				Ref:     "r",
				Session: "some-buildkit-session-uuid",
			}),
			policy:     fullyAllowed,
			wantDenied: false,
		},
		{
			name: "image exporter push=1 (ParseBool truthy) is gated exactly like push=true",
			payload: mustMarshal(t, &control.SolveRequest{
				Ref: "r",
				Exporters: []*control.Exporter{{
					Type:  "image",
					Attrs: map[string]string{"push": "1", "name": "evil.example/img"},
				}},
			}),
			policy: SolvePolicy{
				Allow:                     true,
				AllowedExporters:          []string{"image"},
				AllowedExporterRegistries: []string{"example.com"},
			},
			wantDenied: true,
			wantReason: "buildkit_policy_denied",
			wantCode:   grpcCodePermissionDenied,
		},
		{
			name: "image exporter push=TRUE to an allowed registry is admitted",
			payload: mustMarshal(t, &control.SolveRequest{
				Ref: "r",
				Exporters: []*control.Exporter{{
					Type:  "image",
					Attrs: map[string]string{"push": "TRUE", "name": "example.com/img"},
				}},
			}),
			policy: SolvePolicy{
				Allow:                     true,
				AllowedExporters:          []string{"image"},
				AllowedExporterRegistries: []string{"example.com"},
			},
			wantDenied: false,
		},
		{
			name: "image exporter push value ParseBool cannot evaluate is denied",
			payload: mustMarshal(t, &control.SolveRequest{
				Ref: "r",
				Exporters: []*control.Exporter{{
					Type:  "image",
					Attrs: map[string]string{"push": "sometimes", "name": "example.com/img"},
				}},
			}),
			policy: SolvePolicy{
				Allow:                     true,
				AllowedExporters:          []string{"image"},
				AllowedExporterRegistries: []string{"example.com"},
			},
			wantDenied: true,
			wantReason: "buildkit_policy_denied",
			wantCode:   grpcCodePermissionDenied,
		},
		{
			name: "image exporter push with comma-separated names all on the allowlist is admitted",
			payload: mustMarshal(t, &control.SolveRequest{
				Ref: "r",
				Exporters: []*control.Exporter{{
					Type:  "image",
					Attrs: map[string]string{"push": "true", "name": "example.com/a,example.com/b"},
				}},
			}),
			policy: SolvePolicy{
				Allow:                     true,
				AllowedExporters:          []string{"image"},
				AllowedExporterRegistries: []string{"example.com"},
			},
			wantDenied: false,
		},
		{
			name: "image exporter push with one of several comma-separated names off the allowlist is denied",
			payload: mustMarshal(t, &control.SolveRequest{
				Ref: "r",
				Exporters: []*control.Exporter{{
					Type:  "image",
					Attrs: map[string]string{"push": "true", "name": "example.com/a,evil.example/b"},
				}},
			}),
			policy: SolvePolicy{
				Allow:                     true,
				AllowedExporters:          []string{"image"},
				AllowedExporterRegistries: []string{"example.com"},
			},
			wantDenied: true,
			wantReason: "buildkit_policy_denied",
			wantCode:   grpcCodePermissionDenied,
		},
		{
			name: "image exporter push=true with empty name is denied",
			payload: mustMarshal(t, &control.SolveRequest{
				Ref: "r",
				Exporters: []*control.Exporter{{
					Type:  "image",
					Attrs: map[string]string{"push": "true"},
				}},
			}),
			policy: SolvePolicy{
				Allow:                     true,
				AllowedExporters:          []string{"image"},
				AllowedExporterRegistries: []string{"example.com"},
			},
			wantDenied: true,
			wantReason: "buildkit_policy_denied",
			wantCode:   grpcCodePermissionDenied,
		},
		{
			name: "non-image exporter type ignores push/name entirely",
			payload: mustMarshal(t, &control.SolveRequest{
				Ref: "r",
				Exporters: []*control.Exporter{{
					Type:  "local",
					Attrs: map[string]string{"push": "not-a-bool", "name": "evil.example/img"},
				}},
			}),
			policy: SolvePolicy{
				Allow:            true,
				AllowedExporters: []string{"local"},
			},
			wantDenied: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, d := evaluateSolveRequest(tc.payload, Policy{Control: ControlPolicy{Solve: tc.policy}})
			if tc.wantDenied {
				if d == nil {
					t.Fatal("want a denial, got nil")
				}
				if req != nil {
					t.Fatal("on denial, req must be nil")
				}
				if d.reasonCode != tc.wantReason {
					t.Fatalf("reasonCode = %q, want %q", d.reasonCode, tc.wantReason)
				}
				if d.code != tc.wantCode {
					t.Fatalf("code = %d, want %d", d.code, tc.wantCode)
				}
				return
			}
			if d != nil {
				t.Fatalf("want no denial, got %+v", d)
			}
			if req == nil {
				t.Fatal("on success, req must not be nil")
			}
		})
	}

	t.Run("returns the decoded Ref for admitted requests", func(t *testing.T) {
		req, d := evaluateSolveRequest(mustMarshal(t, &control.SolveRequest{Ref: "build-ref-1"}), Policy{Control: ControlPolicy{Solve: SolvePolicy{Allow: true}}})
		if d != nil {
			t.Fatalf("want admission, got denial %+v", d)
		}
		if req.GetRef() != "build-ref-1" {
			t.Fatalf("Ref = %q, want %q", req.GetRef(), "build-ref-1")
		}
	})
}

func TestEvaluateStatusRequest(t *testing.T) {
	t.Run("malformed payload", func(t *testing.T) {
		req, d := evaluateStatusRequest(malformedPayload)
		if req != nil {
			t.Fatal("on denial, req must be nil")
		}
		if denyReason(d) != "buildkit_protocol_error" {
			t.Fatalf("reasonCode = %q, want buildkit_protocol_error", denyReason(d))
		}
		if d.code != grpcCodeInvalidArgument {
			t.Fatalf("code = %d, want %d", d.code, grpcCodeInvalidArgument)
		}
	})

	t.Run("unknown fields", func(t *testing.T) {
		req := &control.StatusRequest{Ref: "r"}
		req.ProtoReflect().SetUnknown(unknownFieldBytes())
		payload := mustMarshal(t, req)

		decoded, d := evaluateStatusRequest(payload)
		if decoded != nil {
			t.Fatal("on denial, req must be nil")
		}
		if denyReason(d) != "buildkit_schema_unsupported" {
			t.Fatalf("reasonCode = %q, want buildkit_schema_unsupported", denyReason(d))
		}
		if d.code != grpcCodeFailedPrecondition {
			t.Fatalf("code = %d, want %d", d.code, grpcCodeFailedPrecondition)
		}
	})

	t.Run("success", func(t *testing.T) {
		payload := mustMarshal(t, &control.StatusRequest{Ref: "build-ref-1"})
		decoded, d := evaluateStatusRequest(payload)
		if d != nil {
			t.Fatalf("want no denial, got %+v", d)
		}
		if decoded.GetRef() != "build-ref-1" {
			t.Fatalf("Ref = %q, want %q", decoded.GetRef(), "build-ref-1")
		}
	})
}

func TestIsKnownFrontendAttrKey(t *testing.T) {
	cases := []struct {
		key  string
		want bool
	}{
		{"filename", true},
		{"context", true},
		{"force-network-mode", true},
		{"build-arg:FOO", true},
		{"label:org.opencontainers.image.source", true},
		{"context:base", true},
		{"some-unknown-key", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := isKnownFrontendAttrKey(tc.key); got != tc.want {
			t.Errorf("isKnownFrontendAttrKey(%q) = %v, want %v", tc.key, got, tc.want)
		}
	}
}

func TestIsRemoteContextRef(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{"https://example.com/repo.git", true},
		{"http://example.com/repo.git", true},
		{"git://example.com/repo.git", true},
		{"git@example.com:org/repo.git", true},
		{"github.com/org/repo", true},
		{"custom-scheme://thing", true},
		// scp-like git remotes (no "://" at all) — the bypass CodeRabbit
		// flagged: any "<user>@<host>:<path>" shape is a git remote to
		// BuildKit's own gitutil/sshutil, not just a literal "git@" prefix.
		{"bob@example.com:org/repo.git", true},
		{"deploy-key@git.internal.example:team/app.git", true},
		{".", false},
		{"subdir", false},
		{"", false},
		// Looks superficially close to scp-like syntax but isn't: no colon
		// (just a bare user@host, e.g. an email address) or no "@" at all
		// must never match.
		{"user@host", false},
		{"path/with@in/it", false},
		{"@no-user-before-at:path", false},
	}
	for _, tc := range cases {
		if got := isRemoteContextRef(tc.value); got != tc.want {
			t.Errorf("isRemoteContextRef(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestRegistryHostFromImageRef(t *testing.T) {
	cases := []struct {
		ref    string
		want   string
		wantOK bool
	}{
		{"", "", false},
		{"alpine", "docker.io", true},
		{"library/alpine", "docker.io", true},
		{"localhost/foo", "localhost", true},
		{"localhost:5000/foo", "localhost:5000", true},
		{"example.com/foo/bar", "example.com", true},
		{"Example.COM/foo", "example.com", true},
		{"index.docker.io/library/alpine", "docker.io", true},
		{"https://example.com/foo", "example.com", true},
	}
	for _, tc := range cases {
		host, ok := registryHostFromImageRef(tc.ref)
		if ok != tc.wantOK || host != tc.want {
			t.Errorf("registryHostFromImageRef(%q) = (%q, %v), want (%q, %v)", tc.ref, host, ok, tc.want, tc.wantOK)
		}
	}
}

// TestCheckSolveCacheSkipsNilEntries exercises checkSolveCache's per-entry
// nil guard directly against a constructed request holding an actual Go nil
// pointer in a repeated field. A proto.Marshal/Unmarshal round trip cannot
// produce this shape (the wire format has no way to represent "element N is
// absent"; marshaling a nil entry either panics or serializes as an empty
// message depending on the field kind), so this must call the function
// directly rather than go through evaluateSolveRequest's decode path.
func TestCheckSolveCacheSkipsNilEntries(t *testing.T) {
	req := &control.SolveRequest{
		Cache: &control.CacheOptions{
			Imports: []*control.CacheOptionsEntry{nil},
			Exports: []*control.CacheOptionsEntry{nil},
		},
	}
	if d := checkSolveCache(req, SolvePolicy{Allow: true}); d != nil {
		t.Fatalf("nil cache entries must be skipped, got denial %+v", d)
	}
}

// TestCheckSolveExportersSkipsNilEntries is checkSolveCache's sibling for
// checkSolveExporters' inline nil guard — see
// TestCheckSolveCacheSkipsNilEntries's doc comment for why this must call
// the function directly.
func TestCheckSolveExportersSkipsNilEntries(t *testing.T) {
	req := &control.SolveRequest{
		Exporters: []*control.Exporter{nil},
	}
	if d := checkSolveExporters(req, SolvePolicy{Allow: true}); d != nil {
		t.Fatalf("nil exporter entries must be skipped, got denial %+v", d)
	}
}

func TestCheckCacheEntry(t *testing.T) {
	if d := checkCacheEntry(nil, []string{"registry"}, []string{"example.com"}); d != nil {
		t.Fatalf("nil entry must be a no-op, got %+v", d)
	}
}

func TestDeny(t *testing.T) {
	d := deny(grpcCodePermissionDenied, "buildkit_policy_denied", "message text")
	if d.code != grpcCodePermissionDenied || d.reasonCode != "buildkit_policy_denied" || d.message != "message text" {
		t.Fatalf("deny(...) = %+v, unexpected fields", d)
	}
}
