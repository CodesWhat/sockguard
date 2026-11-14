package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/admin"
	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

func TestPolicyDiffComparesRunningGeneration(t *testing.T) {
	cfg := config.Defaults()
	cfg.Admin.Enabled = true
	versioner := admin.NewPolicyVersioner()
	versioner.Update(buildInitialPolicySnapshot(newServeTestDeps(), &cfg, nil, false, nil))
	handler := buildAdminHandlerChain(&cfg, newDiscardLogger(), nil, versioner)
	req := httptest.NewRequest(http.MethodPost, "/admin/policy/diff", strings.NewReader("admin:\n  enabled: true\nresponse:\n  redact_container_env: false\n"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("diff status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		OK          bool  `json:"ok"`
		BaseVersion int64 `json:"base_version"`
		Changed     bool  `json:"changed"`
		Changes     []struct {
			Path string `json:"path"`
			Kind string `json:"kind"`
		} `json:"changes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.OK || !response.Changed || response.BaseVersion != 1 || len(response.Changes) != 1 {
		t.Fatalf("unexpected diff: %s", rec.Body.String())
	}
	if got := response.Changes[0]; got.Path != "response.redact_container_env" || got.Kind != "modified" {
		t.Fatalf("unexpected change: %+v", got)
	}
	if versioner.Snapshot().Version != 1 || !cfg.Response.RedactContainerEnv {
		t.Fatal("read-only comparison changed the active policy")
	}
}

func TestPolicyDiffRejectsCandidatesWithoutEchoingValues(t *testing.T) {
	cfg := config.Defaults()
	snap := &admin.PolicySnapshot{Config: &cfg, Version: 1}
	for _, candidate := range []string{
		"private-value: [",
		"rules:\n  - match: { method: GET, path: /version }\n    action: private-value\n",
	} {
		result := compareAdminPolicy([]byte(candidate), snap)
		body, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		if result.OK || result.Error == "" || strings.Contains(string(body), "private-value") {
			t.Fatalf("unsafe invalid-candidate response: %s", body)
		}
	}
}

func TestPolicyDiffReportsIgnoredUnknownKeys(t *testing.T) {
	cfg := config.Defaults()
	result := compareAdminPolicy([]byte("private-setting: private-value\n"), &admin.PolicySnapshot{Config: &cfg, Version: 1})
	body, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK || result.Changed || result.UnknownKeys != 1 || strings.Contains(string(body), "private-") {
		t.Fatalf("unexpected ignored-key response: %s", body)
	}
}

func TestPolicyDiffDoesNotReadCandidateTLSFiles(t *testing.T) {
	cfg := config.Defaults()
	dir := t.TempDir()
	present := filepath.Join(dir, "present.txt")
	if err := os.WriteFile(present, []byte("private-file-content"), 0o600); err != nil {
		t.Fatal(err)
	}
	var baseline string
	for _, path := range []string{present, filepath.Join(dir, "absent.pem")} {
		result := compareAdminPolicy(candidateWithTLSPaths(path), &admin.PolicySnapshot{Config: &cfg, Version: 1})
		body, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		if !result.OK || strings.Contains(string(body), dir) || strings.Contains(string(body), "private-file-content") {
			t.Fatalf("unsafe TLS comparison: %s", body)
		}
		if baseline == "" {
			baseline = string(body)
		} else if baseline != string(body) {
			t.Fatalf("TLS file existence changed comparison: %s vs %s", baseline, body)
		}
	}
}

func TestPolicyDiffTracksSuccessfulReloadOnly(t *testing.T) {
	initial := config.Defaults()
	initial.Admin.Enabled = true
	f := newReloadCoordinatorFixture(t, &initial)
	f.versioner.Update(buildInitialPolicySnapshot(newServeTestDeps(), &initial, nil, false, nil))
	h := buildAdminHandlerChain(&initial, newDiscardLogger(), nil, f.versioner)
	body := "admin:\n  enabled: true\nresponse:\n  redact_container_env: false\n"
	candidate, err := config.LoadBytes([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	f.loadCfg = candidate
	f.coordinator.reload()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/admin/policy/diff", strings.NewReader(body)))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"base_version":2`) || !strings.Contains(rec.Body.String(), `"changed":false`) {
		t.Fatalf("comparison did not follow applied generation: %d %s", rec.Code, rec.Body.String())
	}
	rejected := *candidate
	rejected.Admin.Path = "/different-admin"
	f.loadCfg = &rejected
	f.coordinator.reload()
	if f.versioner.Snapshot().Version != 2 || f.versioner.Snapshot().Config != candidate {
		t.Fatal("rejected reload replaced comparison generation")
	}
}

func TestPolicyDiffReportsStructuralValidationAndRestart(t *testing.T) {
	cfg := config.Defaults()
	v := admin.NewPolicyVersioner()
	v.Update(buildInitialPolicySnapshot(newServeTestDeps(), &cfg, nil, false, nil))
	h := withPolicyDiffEndpoint(&cfg, newDiscardLogger(), v)(http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/admin/policy/diff", strings.NewReader("listen:\n  address: 127.0.0.1:4321\n")))
	var result struct {
		Validation      string `json:"validation"`
		RestartRequired bool   `json:"restart_required"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if rec.Code != 200 || result.Validation != "structural" || !result.RestartRequired {
		t.Fatalf("missing applicability information: %d %s", rec.Code, rec.Body.String())
	}
}

func TestPolicyDiffRespectsAdminAccessBoundary(t *testing.T) {
	for _, tt := range []struct {
		name      string
		enabled   bool
		dedicated bool
		cidr      string
		want      int
	}{
		{"main enabled", true, false, "", 200},
		{"disabled", false, false, "", 403},
		{"dedicated absent from main", true, true, "", 403},
		{"main denied CIDR", true, false, "10.0.0.0/8", 403},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Admin.Enabled = tt.enabled
			cfg.Upstream.Socket = shortSocketPath(t, "diff-boundary")
			if tt.dedicated {
				cfg.Admin.Listen.Address = "127.0.0.1:0"
			}
			if tt.cidr != "" {
				cfg.Clients.AllowedCIDRs = []string{tt.cidr}
			}
			logger, deps := newDiscardLogger(), newServeTestDeps()
			runtime, err := newServeRuntime(&cfg, logger, deps)
			if err != nil {
				t.Fatal(err)
			}
			v := admin.NewPolicyVersioner()
			v.Update(buildInitialPolicySnapshot(deps, &cfg, nil, false, nil))
			h, stop, _ := buildServeHandlerChainWithRuntime(serveHandlerBuild{Cfg: &cfg, Logger: logger, Rules: adminTestRules(t), Deps: deps, Runtime: runtime, Versioner: v})
			t.Cleanup(stop)
			req := httptest.NewRequest("POST", "/admin/policy/diff", strings.NewReader("admin:\n  enabled: true\n"))
			req.Header.Set("Content-Type", "application/yaml")
			req.RemoteAddr = "192.0.2.1:1234"
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("status=%d want=%d; body=%s", rec.Code, tt.want, rec.Body.String())
			}
		})
	}
	t.Run("dedicated CIDR backstop", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.Admin.Enabled = true
		cfg.Admin.Listen.Address = "127.0.0.1:0"
		cfg.Clients.AllowedCIDRs = []string{"10.0.0.0/8"}
		v := admin.NewPolicyVersioner()
		v.Update(buildInitialPolicySnapshot(newServeTestDeps(), &cfg, nil, false, nil))
		h := buildAdminHandlerChain(&cfg, newDiscardLogger(), nil, v)
		req := httptest.NewRequest("POST", "/admin/policy/diff", strings.NewReader(""))
		req.RemoteAddr = "192.0.2.1:1234"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 403 {
			t.Fatalf("dedicated admin CIDR bypass: %d %s", rec.Code, rec.Body.String())
		}
	})
}
