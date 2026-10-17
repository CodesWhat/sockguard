package config

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/filter"
)

func podmanBuildControlHandler(t *testing.T, yaml string) http.Handler {
	t.Helper()
	cfg, err := LoadBytes([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if err = ValidateStructural(cfg); err != nil {
		t.Fatal(err)
	}
	rule, err := filter.CompileRule(filter.Rule{Methods: []string{"POST"}, Pattern: "/**", Action: filter.ActionAllow})
	if err != nil {
		t.Fatal(err)
	}
	policy := cfg.RequestBody.ToFilterOptions()
	policy.Build.PodmanUpstream = true
	return filter.MiddlewareWithOptions([]*filter.CompiledRule{rule}, discardLogger, filter.Options{PolicyConfig: policy})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
}

func TestPodmanRunBuildControlsRequireSpecificGrants(t *testing.T) {
	for _, route := range []string{"/build", "/v1.47/build", "/libpod/build", "/v6.0.0/libpod/build"} {
		for _, name := range []string{"nsoptions", "addcaps", "devices", "securityopt", "seccomp", "apparmor", "labelopts", "idmappingoptions", "groupadd", "cgroupparent", "ulimits", "shmsize", "dnsservers", "dnssearch", "dnsoptions", "from", "extrahosts", "isolation"} {
			for _, allow := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/%v", route, name, allow), func(t *testing.T) {
					grant := "[]"
					if allow {
						grant = "[" + name + "]"
					}
					handler := podmanBuildControlHandler(t, "request_body:\n  build: {allow_run_instructions: true, allow_host_network: true, allowed_podman_controls: "+grant+"}\n")
					rec := httptest.NewRecorder()
					handler.ServeHTTP(rec, httptest.NewRequest("POST", route+"?"+url.QueryEscape(name)+"=client-value", nil))
					want := 403
					if allow {
						want = 200
					}
					if rec.Code != want {
						t.Fatalf("status %d, want %d: %s", rec.Code, want, rec.Body)
					}
				})
			}
		}
	}
}

func TestPodmanBuildControlGrantValidation(t *testing.T) {
	for _, name := range []string{"device", "*", "DEVICES", "unknown"} {
		cfg, err := LoadBytes([]byte(fmt.Sprintf("request_body:\n  build: {allowed_podman_controls: [%q]}\n", name)))
		if err == nil {
			err = ValidateStructural(cfg)
		}
		if err == nil {
			t.Errorf("accepted unsupported control %q", name)
		}
	}
	for _, query := range []string{"Devices=a", "devices=a&devices=b", "ſeccomp=a"} {
		handler := podmanBuildControlHandler(t, "request_body:\n  build: {allow_run_instructions: true, allow_host_network: true, allowed_podman_controls: [devices, seccomp]}\n")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest("POST", "/build?"+query, strings.NewReader("")))
		if rec.Code != 403 {
			t.Fatalf("ambiguous query %s: %d", query, rec.Code)
		}
	}
}
