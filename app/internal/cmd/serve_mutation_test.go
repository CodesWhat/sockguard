package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/config"
)

type mutationUpstreamRequest struct {
	path     string
	rawQuery string
	body     []byte
}

func TestBuildServeHandlerAdmissionMutationsPerSurface(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		body      string
		configure func(*config.Config)
		assert    func(*testing.T, mutationUpstreamRequest)
	}{
		{
			name: "container create injection satisfies downstream required label",
			path: "/v1.53/containers/create",
			body: `{"Image":"alpine:3.21","labels":{"com.example.mandatory":"client"}}`,
			configure: func(cfg *config.Config) {
				cfg.RequestBody.ContainerCreate.RequiredLabels = []string{"com.example.mandatory"}
				cfg.Mutations.Rules = []config.MutationRuleConfig{{
					ID:       "container-label",
					Mode:     "enforce",
					Surfaces: []string{"container_create"},
					InjectLabels: &config.InjectLabelsMutationConfig{Labels: map[string]string{
						"com.example.mandatory": "canonical",
					}},
				}}
			},
			assert: func(t *testing.T, got mutationUpstreamRequest) {
				t.Helper()
				var doc map[string]any
				if err := json.Unmarshal(got.body, &doc); err != nil {
					t.Fatalf("decode upstream body: %v", err)
				}
				labels := doc["Labels"].(map[string]any)
				if labels["com.example.mandatory"] != "canonical" {
					t.Fatalf("upstream Labels = %#v, want canonical mandatory label", labels)
				}
				if strings.Contains(string(got.body), `"labels"`) {
					t.Fatalf("upstream body retained noncanonical labels field: %s", got.body)
				}
			},
		},
		{
			name: "service create mutates both label maps and image",
			path: "/v1.53/services/create",
			body: `{"Labels":{},"TaskTemplate":{"ContainerSpec":{"Image":"source.example/team/app:v1","Labels":{}}}}`,
			configure: func(cfg *config.Config) {
				cfg.RequestBody.Service.AllowedRegistries = []string{"mirror.example"}
				cfg.Mutations.Rules = []config.MutationRuleConfig{
					{
						ID:           "service-labels",
						Mode:         "enforce",
						Surfaces:     []string{"service_create"},
						InjectLabels: &config.InjectLabelsMutationConfig{Labels: map[string]string{"com.example.team": "platform"}},
					},
					{
						ID:       "service-image",
						Mode:     "enforce",
						Surfaces: []string{"service_create"},
						RemapImage: &config.ImageRemapMutationConfig{
							Match: "prefix",
							From:  "source.example/",
							To:    "mirror.example/",
						},
					},
				}
			},
			assert: func(t *testing.T, got mutationUpstreamRequest) {
				t.Helper()
				var doc map[string]any
				if err := json.Unmarshal(got.body, &doc); err != nil {
					t.Fatalf("decode upstream body: %v", err)
				}
				rootLabels := doc["Labels"].(map[string]any)
				spec := doc["TaskTemplate"].(map[string]any)["ContainerSpec"].(map[string]any)
				taskLabels := spec["Labels"].(map[string]any)
				if rootLabels["com.example.team"] != "platform" || taskLabels["com.example.team"] != "platform" {
					t.Fatalf("root Labels=%#v task Labels=%#v, want mutation in both maps", rootLabels, taskLabels)
				}
				if spec["Image"] != "mirror.example/team/app:v1" {
					t.Fatalf("upstream service image = %#v, want remapped target", spec["Image"])
				}
			},
		},
		{
			name: "service update mutates image and preserves version query",
			path: "/v1.53/services/svc-1/update?version=17",
			body: `{"TaskTemplate":{"ContainerSpec":{"Image":"source.example/app:v1"}},"Version":{"Index":9007199254740993}}`,
			configure: func(cfg *config.Config) {
				cfg.RequestBody.Service.AllowedRegistries = []string{"mirror.example"}
				cfg.Mutations.Rules = []config.MutationRuleConfig{{
					ID:       "update-image",
					Mode:     "enforce",
					Surfaces: []string{"service_update"},
					RemapImage: &config.ImageRemapMutationConfig{
						Match: "exact",
						From:  "source.example/app:v1",
						To:    "mirror.example/app:v2",
					},
				}}
			},
			assert: func(t *testing.T, got mutationUpstreamRequest) {
				t.Helper()
				if got.rawQuery != "version=17" {
					t.Fatalf("upstream query = %q, want version=17", got.rawQuery)
				}
				if !strings.Contains(string(got.body), `"Image":"mirror.example/app:v2"`) {
					t.Fatalf("upstream body = %s, want remapped update image", got.body)
				}
				if strings.Contains(string(got.body), `"Labels"`) {
					t.Fatalf("service update unexpectedly gained Labels: %s", got.body)
				}
				if !strings.Contains(string(got.body), "9007199254740993") {
					t.Fatalf("upstream body corrupted large integer: %s", got.body)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstreamRequests := make(chan mutationUpstreamRequest, 1)
			upstreamHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				upstreamRequests <- mutationUpstreamRequest{path: r.URL.Path, rawQuery: r.URL.RawQuery, body: body}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, `{}`)
			})

			cfg := config.Defaults()
			cfg.Upstream.Socket = shortSocketPath(t, "mutation-chain")
			cfg.Health.Enabled = false
			cfg.Log.AccessLog = false
			tt.configure(&cfg)
			if err := config.Validate(&cfg); err != nil {
				t.Fatalf("test config validation: %v", err)
			}
			rules, err := compileRuleConfigsForTest([]config.RuleConfig{
				{Match: config.MatchConfig{Method: http.MethodPost, Path: "/**"}, Action: "allow"},
				{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "deny all"},
			})
			if err != nil {
				t.Fatalf("compile rules: %v", err)
			}
			var handler http.Handler = upstreamHandler
			layers := buildServeHandlerLayers(&cfg, newDiscardLogger(), nil, rules, newServeTestDeps(), nil)
			for _, layer := range layers {
				handler = layer.with(handler)
			}
			req := httptest.NewRequest(http.MethodPost, tt.path, strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
			}
			select {
			case got := <-upstreamRequests:
				if got.path != strings.Split(tt.path, "?")[0] {
					t.Fatalf("upstream path = %q, want %q", got.path, strings.Split(tt.path, "?")[0])
				}
				tt.assert(t, got)
			default:
				t.Fatal("upstream was not called")
			}
		})
	}
}
