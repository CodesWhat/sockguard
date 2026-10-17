package buildkitproxy

import (
	"context"
	"maps"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/buildkitproto/control"
	"google.golang.org/protobuf/proto"
)

func TestBuildxExporterCompatibilityCopy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*control.SolveRequest)
		want   string
	}{
		{"matching current client", func(*control.SolveRequest) {}, ""},
		{"legacy only", func(r *control.SolveRequest) { r.Exporters = nil }, "buildkit_schema_unsupported"},
		{"conflicting kind", func(r *control.SolveRequest) { r.ExporterDeprecated = "local" }, "buildkit_schema_unsupported"},
		{"conflicting name", func(r *control.SolveRequest) { r.ExporterAttrsDeprecated["name"] = "foreign/image:latest" }, "buildkit_schema_unsupported"},
		{"extra legacy attribute", func(r *control.SolveRequest) { r.ExporterAttrsDeprecated["push"] = "true" }, "buildkit_schema_unsupported"},
		{"missing legacy kind", func(r *control.SolveRequest) { r.ExporterDeprecated = "" }, "buildkit_schema_unsupported"},
		{"ungranted exporter", func(r *control.SolveRequest) { r.ExporterDeprecated = "local"; r.Exporters[0].Type = "local" }, "buildkit_policy_denied"},
		{"ungranted registry", func(r *control.SolveRequest) {
			r.ExporterDeprecated, r.Exporters[0].Type = "image", "image"
			r.Exporters[0].Attrs["name"] = "foreign.example/image:latest"
			r.Exporters[0].Attrs["push"] = "true"
			r.ExporterAttrsDeprecated = maps.Clone(r.Exporters[0].Attrs)
		}, "buildkit_policy_denied"},
		{"ungranted second exporter", func(r *control.SolveRequest) { r.Exporters = append(r.Exporters, &control.Exporter{Type: "local"}) }, "buildkit_policy_denied"},
		{"legacy cache still denied", func(r *control.SolveRequest) { r.Cache.ExportRefDeprecated = "foreign.example/cache:latest" }, "buildkit_schema_unsupported"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Buildx v0.33.0's captured Solve has both exporter representations.
			r := &control.SolveRequest{Ref: "buildx", Session: testBuildkitSessionID,
				FrontendAttrs:      map[string]string{"filename": "Dockerfile", "image-resolve-mode": "local"},
				ExporterDeprecated: "moby", ExporterAttrsDeprecated: map[string]string{"name": "example.com/team/image:latest"},
				Exporters: []*control.Exporter{{Type: "moby", Attrs: map[string]string{"name": "example.com/team/image:latest"}}},
				Cache:     &control.CacheOptions{}}
			tc.change(r)
			policy := Policy{Control: ControlPolicy{Solve: SolvePolicy{Allow: true, AllowedExporters: []string{"moby", "image"}, AllowedExporterRegistries: []string{"example.com"}}}}
			_, d := evaluateSolveRequest(mustMarshal(t, r), policy)
			if got := denyReason(d); got != tc.want {
				t.Fatalf("reason=%q, want %q", got, tc.want)
			}
		})
	}
}

func TestBuildxExporterOwnershipCopiesStayEqual(t *testing.T) {
	policy := allowAllPolicy
	policy.Control.Solve.AllowedExporters = []string{"image"}
	policy.ImageOwnership = ImageOwnershipPolicy{Owner: "team-a", LabelKey: "owner", Authorize: func(context.Context, string) error { return nil }}
	var called atomic.Bool
	tb := newTestBridge(t, EndpointGRPC, policy, DefaultLimits(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Store(true)
		_, raw, err := readGRPCFrame(r.Body, DefaultLimits().MaxMessageBytes)
		if err != nil {
			t.Error(err)
			return
		}
		var got control.SolveRequest
		if err := proto.Unmarshal(raw, &got); err != nil {
			t.Error(err)
			return
		}
		if !maps.Equal(got.ExporterAttrsDeprecated, got.Exporters[0].Attrs) {
			t.Error("legacy exporter lost the owner mutation")
		}
		if !strings.Contains(got.Exporters[0].Attrs[imageConfigKey], `"owner":"team-a"`) {
			t.Error("owner was not stamped")
		}
		writeGRPCStatus(w, 0, "")
	}))
	attrs := map[string]string{"name": "mine/app:v1", imageConfigKey: `{"config":{"Labels":{"owner":"forged"}}}`}
	r := &control.SolveRequest{Ref: "buildx", Session: testBuildkitSessionID, ExporterDeprecated: "image", ExporterAttrsDeprecated: maps.Clone(attrs), Exporters: []*control.Exporter{{Type: "image", Attrs: attrs}}}
	resp, err := tb.driver.RoundTrip(newFramedGRPCRequest(t, "/moby.buildkit.v1.Control/Solve", r))
	if err != nil {
		t.Fatal(err)
	}
	code, _ := grpcStatusOf(t, resp)
	if code != 0 || !called.Load() {
		t.Fatalf("status=%d daemon=%v", code, called.Load())
	}
}
