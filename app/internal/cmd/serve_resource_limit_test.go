package cmd

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/filter"
	"github.com/codeswhat/sockguard/app/internal/logging"
	"github.com/codeswhat/sockguard/app/internal/ownership"
	"github.com/codeswhat/sockguard/app/internal/testhelp"
)

type serveResourceRoundTripFunc func(*http.Request) (*http.Response, error)

func (f serveResourceRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestResourceLimitGuardRunsStrictlyAfterOwnership(t *testing.T) {
	cfg := config.Defaults()
	names := serveHandlerLayerNames(buildServeHandlerLayers(&cfg, newDiscardLogger(), nil, nil, newServeTestDeps(), nil))
	index := func(name string) int {
		t.Helper()
		for i, got := range names {
			if got == name {
				return i
			}
		}
		t.Fatalf("layer %q not found in %v", name, names)
		return -1
	}
	// Layers later in the append-order slice wrap and execute before earlier
	// layers. Ownership therefore must have the larger index.
	if ownerIndex, guardIndex := index("withOwnership"), index("withResourceLimitGuard"); ownerIndex <= guardIndex {
		t.Fatalf("layer order = %v: ownership index %d must be greater than guard index %d", names, ownerIndex, guardIndex)
	}

	inspectCalls := 0
	rt := serveResourceRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		inspectCalls++
		if inspectCalls > 1 {
			t.Fatalf("resource-limit GET ran after ownership should have denied: %s %s", r.Method, r.URL.Path)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body: io.NopCloser(strings.NewReader(
				`{"Config":{"Labels":{"com.sockguard.owner":"tenant-b"}},"HostConfig":{"Memory":0}}`,
			)),
		}, nil
	})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	policy := filter.PolicyConfig{
		DenyResponseVerbosity: filter.DenyResponseVerbosityVerbose,
		ContainerUpdate: filter.ContainerUpdateOptions{
			AllowResourceUpdates: true,
			RequireMemoryLimit:   true,
		},
	}
	guard := filter.ResourceLimitGuardWithOptions(logger, filter.ResourceLimitGuardOptions{
		PolicyConfig:     policy,
		InspectContainer: filter.NewDockerContainerUpdateInspectorWithRoundTripper(rt),
	})
	upstreamCalls := 0
	upstream := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { upstreamCalls++ })
	handler := ownership.MiddlewareWithRoundTripper(rt, logger, ownership.Options{
		Owner:    "tenant-a",
		LabelKey: "com.sockguard.owner",
	})(guard(upstream))

	meta := &logging.RequestMeta{}
	req := httptest.NewRequest(http.MethodPost, "/containers/foreign/update", strings.NewReader(`{}`))
	req = req.WithContext(logging.WithMeta(req.Context(), meta))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want ownership 403; body: %s", rec.Code, rec.Body.String())
	}
	if meta.ReasonCode != "owner_policy_denied_access" {
		t.Fatalf("reason code = %q, want owner_policy_denied_access", meta.ReasonCode)
	}
	if inspectCalls != 1 {
		t.Fatalf("daemon GET calls = %d, want exactly ownership's one GET", inspectCalls)
	}
	if upstreamCalls != 0 {
		t.Fatalf("upstream update calls = %d, want 0", upstreamCalls)
	}
	if meta.ResourcePolicy != nil {
		t.Fatalf("ResourcePolicy = %#v, want nil because resource guard never ran", meta.ResourcePolicy)
	}
}

func TestResourceLimitRequireWarningFiresExactlyOnce(t *testing.T) {
	collector := &testhelp.CollectingHandler{}
	once := &sync.Once{}
	cfg := config.Defaults()
	cfg.RequestBody.ContainerUpdate.RequireMemoryLimit = true

	warnResourceLimitRequireOnce(&cfg, collector.Logger(), once)
	warnResourceLimitRequireOnce(&cfg, collector.Logger(), once)
	cfg.Clients.Profiles = []config.ClientProfileConfig{{
		Name: "also-misconfigured",
		RequestBody: config.RequestBodyConfig{
			ContainerUpdate: config.ContainerUpdateRequestBodyConfig{RequirePidsLimit: true},
		},
	}}
	warnResourceLimitRequireOnce(&cfg, collector.Logger(), once)

	const message = "request_body.container_update (default policy and/or one or more client profiles) has a require_* resource-limit flag enabled while allow_resource_updates is false: the flag is currently a no-op there — the existing blanket deny of resource-control fields already blocks every resource update, so set allow_resource_updates: true to activate the require_* check, or drop the require_* flag to avoid confusion"
	if got := len(collector.FindMessage(message)); got != 1 {
		t.Fatalf("warning count = %d, want exactly 1; records: %#v", got, collector.Records())
	}
}

func TestResourceLimitRequireWarningCoversDefaultAndProfiles(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*config.Config)
		wantWarn  bool
	}{
		{
			name:      "no requirements",
			configure: func(*config.Config) {},
		},
		{
			name: "default gate open",
			configure: func(cfg *config.Config) {
				cfg.RequestBody.ContainerUpdate.AllowResourceUpdates = true
				cfg.RequestBody.ContainerUpdate.RequireCPULimit = true
			},
		},
		{
			name: "default gate closed",
			configure: func(cfg *config.Config) {
				cfg.RequestBody.ContainerUpdate.RequireCPULimitHard = true
			},
			wantWarn: true,
		},
		{
			name: "profile gate closed",
			configure: func(cfg *config.Config) {
				cfg.Clients.Profiles = []config.ClientProfileConfig{{
					Name:        "strict",
					RequestBody: config.RequestBodyConfig{ContainerUpdate: config.ContainerUpdateRequestBodyConfig{RequirePidsLimit: true}},
				}}
			},
			wantWarn: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Defaults()
			tt.configure(&cfg)
			collector := &testhelp.CollectingHandler{}
			warnResourceLimitRequireOnce(&cfg, collector.Logger(), &sync.Once{})
			gotWarn := len(collector.Records()) > 0
			if gotWarn != tt.wantWarn {
				t.Fatalf("warning emitted = %v, want %v; records: %#v", gotWarn, tt.wantWarn, collector.Records())
			}
		})
	}
}

func TestCompileClientProfilesMapsResourceLimitRequirements(t *testing.T) {
	cfg := config.Defaults()
	cfg.Clients.Profiles = []config.ClientProfileConfig{{
		Name: "strict",
		Rules: []config.RuleConfig{{
			Match:  config.MatchConfig{Method: "*", Path: "/**"},
			Action: "deny",
		}},
		RequestBody: config.RequestBodyConfig{
			ContainerUpdate: config.ContainerUpdateRequestBodyConfig{
				AllowResourceUpdates: true,
				RequireMemoryLimit:   true,
				RequireCPULimit:      true,
				RequireCPULimitHard:  true,
				RequirePidsLimit:     true,
			},
			Service: config.ServiceRequestBodyConfig{
				RequireCPULimit:     true,
				RequireCPULimitHard: true,
			},
		},
	}}

	profiles, err := compileClientProfiles(&cfg)
	if err != nil {
		t.Fatalf("compileClientProfiles() error = %v", err)
	}
	policy, ok := profiles["strict"]
	if !ok {
		t.Fatalf("profiles = %#v, missing strict", profiles)
	}
	cu := policy.ContainerUpdate
	svc := policy.Service
	if !cu.AllowResourceUpdates || !cu.RequireMemoryLimit || !cu.RequireCPULimit || !cu.RequireCPULimitHard || !cu.RequirePidsLimit || !svc.RequireCPULimit || !svc.RequireCPULimitHard {
		t.Fatalf("compiled profile mapping incomplete: container_update=%+v service=%+v", cu, svc)
	}
}
