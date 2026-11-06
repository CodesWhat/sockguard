package cmd

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/clientacl"
	"github.com/codeswhat/sockguard/v3/app/internal/filter"
	"github.com/codeswhat/sockguard/v3/app/internal/upstreamflavor"
)

func TestWithFilterCarriesEngineFlavorIntoProfiles(t *testing.T) {
	t.Parallel()
	for _, flavor := range []upstreamflavor.Flavor{upstreamflavor.Docker, upstreamflavor.Podman} {
		for _, namedProfile := range []bool{false, true} {
			for _, operation := range []struct{ name, path, body, contentType string }{
				{name: "container tmpfs", path: "/containers/create", body: `{"Image":"example","HostConfig":{"Tmpfs":{"/cache":"rw"}}}`, contentType: "application/json"},
				{name: "build private network", path: "/build", contentType: "application/x-tar"},
			} {
				t.Run(string(flavor)+"/"+map[bool]string{false: "global", true: "profile"}[namedProfile]+"/"+operation.name, func(t *testing.T) {
					cfg := flavorTestConfig("auto")
					cfg.RequestBody.Build.AllowRunInstructions = true
					rule, err := filter.CompileRule(filter.Rule{Methods: []string{http.MethodPost}, Pattern: operation.path, Action: filter.ActionAllow})
					if err != nil {
						t.Fatal(err)
					}
					rules := []*filter.CompiledRule{rule}
					profiles := map[string]filter.Policy{}
					if namedProfile {
						profiles["client"] = filter.Policy{Rules: rules, PolicyConfig: cfg.RequestBody.ToFilterOptions()}
					}
					logger, _ := flavorTestLogger()
					handler := withFilter(cfg, nil, logger, rules, profiles, flavor, nil, flavor == upstreamflavor.Docker)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusNoContent)
					}))
					if namedProfile {
						handler = clientacl.MiddlewareWithRoundTripper(nil, logger, clientacl.Options{Profiles: clientacl.ProfileOptions{DefaultProfile: "client"}})(handler)
					}
					req := httptest.NewRequest(http.MethodPost, operation.path, strings.NewReader(operation.body))
					req.Header.Set("Content-Type", operation.contentType)
					rec := httptest.NewRecorder()
					handler.ServeHTTP(rec, req)
					want := http.StatusNoContent
					if flavor == upstreamflavor.Podman {
						want = http.StatusForbidden
					}
					if rec.Code != want {
						t.Fatalf("status=%d, want %d: %s", rec.Code, want, rec.Body.String())
					}
				})
			}
		}
	}
}
