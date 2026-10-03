package filter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// distributionRules allows the inspect route the daemon serves and denies
// everything else, so a denial in these tests is the inspector's and not a
// missing allow rule.
func distributionRules(t *testing.T) []*CompiledRule {
	t.Helper()
	allow, err := CompileRule(Rule{Methods: []string{http.MethodGet}, Pattern: "/distribution/**/json", Action: ActionAllow, Index: 0})
	if err != nil {
		t.Fatalf("compile allow rule: %v", err)
	}
	deny, err := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 1})
	if err != nil {
		t.Fatalf("compile deny rule: %v", err)
	}
	return []*CompiledRule{allow, deny}
}

func serveDistribution(t *testing.T, opts ImagePullOptions, target string) *httptest.ResponseRecorder {
	t.Helper()
	reached := false
	handler := MiddlewareWithOptions(distributionRules(t), testLogger(), Options{
		PolicyConfig: PolicyConfig{
			DenyResponseVerbosity: DenyResponseVerbosityVerbose,
			ImagePull:             opts,
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	if rec.Code == http.StatusOK && !reached {
		t.Fatal("200 without reaching upstream")
	}
	return rec
}

// TestDistributionAppliesImagePullRegistryAllowlist is S38: GET
// /distribution/{name}/json makes the daemon contact whatever registry the
// client names, and that route was not checked against
// request_body.image_pull.allowed_registries. The same allowlist the pull
// inspector uses now applies here.
func TestDistributionAppliesImagePullRegistryAllowlist(t *testing.T) {
	tests := []struct {
		name       string
		opts       ImagePullOptions
		target     string
		wantStatus int
		wantReason string // substring expected in a denial reason
	}{
		{
			name:       "allowlisted registry is allowed",
			opts:       ImagePullOptions{AllowedRegistries: []string{"ghcr.io"}},
			target:     "/v1.45/distribution/ghcr.io/acme/app/json",
			wantStatus: http.StatusOK,
		},
		{
			name:       "non-allowlisted registry is denied",
			opts:       ImagePullOptions{AllowedRegistries: []string{"ghcr.io"}},
			target:     "/v1.45/distribution/quay.io/acme/app/json",
			wantStatus: http.StatusForbidden,
			wantReason: "quay.io",
		},
		{
			name:       "official image is allowed when allow_official and an allowlist are set",
			opts:       ImagePullOptions{AllowOfficial: true, AllowedRegistries: []string{"ghcr.io"}},
			target:     "/v1.45/distribution/alpine/json",
			wantStatus: http.StatusOK,
		},
		{
			name:       "allow_all_registries keeps the route open",
			opts:       ImagePullOptions{AllowAllRegistries: true, AllowedRegistries: []string{"ghcr.io"}},
			target:     "/v1.45/distribution/quay.io/acme/app/json",
			wantStatus: http.StatusOK,
		},
		{
			// The load-bearing unchanged-behavior case: with no allowlist
			// configured the route stays exactly as open as it was before S38,
			// even though the config-layer default sets allow_official.
			name:       "no allowlist configured leaves the route unchanged",
			opts:       ImagePullOptions{AllowOfficial: true},
			target:     "/v1.45/distribution/quay.io/acme/app/json",
			wantStatus: http.StatusOK,
		},
		{
			name:       "registry port is not mistaken for a tag",
			opts:       ImagePullOptions{AllowedRegistries: []string{"registry.example:5000"}},
			target:     "/v1.45/distribution/registry.example:5000/team/app/json",
			wantStatus: http.StatusOK,
		},
		{
			name:       "tagged non-allowlisted reference is denied",
			opts:       ImagePullOptions{AllowedRegistries: []string{"ghcr.io"}},
			target:     "/v1.45/distribution/quay.io/acme/app:v1/json",
			wantStatus: http.StatusForbidden,
			wantReason: "quay.io",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := serveDistribution(t, tt.opts, tt.target)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if tt.wantReason != "" {
				var body DenialResponse
				if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
					t.Fatalf("decode response: %v", err)
				}
				if !strings.Contains(body.Reason, tt.wantReason) {
					t.Fatalf("reason = %q, want substring %q", body.Reason, tt.wantReason)
				}
			}
		})
	}
}

func TestIsDistributionInspectPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/distribution/alpine/json", true},
		{"/distribution/ghcr.io/acme/app/json", true},
		{"/distribution/registry.example:5000/team/app/json", true},
		{"/distribution//json", false},
		{"/distribution/json", false},
		{"/distribution/alpine", false},
		{"/images/alpine/json", false},
		{"/distribution/alpine/json/extra", false},
	}
	for _, tt := range tests {
		if got := isDistributionInspectPath(tt.path); got != tt.want {
			t.Errorf("isDistributionInspectPath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}
