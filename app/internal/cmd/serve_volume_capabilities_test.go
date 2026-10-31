package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/config"
	"github.com/codeswhat/sockguard/v2/app/internal/filter"
)

func TestServeChainUsesVerifiedPodmanVolumeSemantics(t *testing.T) {
	t.Parallel()
	for _, engineVersion := range []string{"5.8.1", "6.0.0", ""} {
		for _, path := range []string{"/volumes", "/libpod/volumes/json"} {
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				t.Run(engineVersion+path+method, func(t *testing.T) {
					t.Parallel()
					seen := make(chan url.Values, 1)
					address := newEngineChain(t, "volume-capability", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.URL.Path == "/version" {
							_, _ = fmt.Fprintf(w, `{"Components":[{"Name":"Podman Engine","Version":%q}]}`, engineVersion)
							return
						}
						if filter.NormalizePath(r.URL.Path) != path {
							t.Errorf("unexpected upstream path %s", r.URL.Path)
							w.WriteHeader(500)
							return
						}
						seen <- r.URL.Query()
						w.Header().Set("Content-Type", "application/json")
						if path == "/volumes" {
							_, _ = w.Write([]byte(`{"Volumes":[],"Warnings":[]}`))
						} else {
							_, _ = w.Write([]byte(`[]`))
						}
					}), func(cfg *config.Config) {
						cfg.Upstream.Flavor = "auto"
						cfg.Ownership.Owner = "job-123"
						cfg.Response.VisibleResourceLabels = []string{"com.sockguard.visible=true"}
						cfg.Rules = []config.RuleConfig{{Match: config.MatchConfig{Method: method, Path: "/**"}, Action: "allow"}}
					})
					query := url.Values{"filters": {`{"driver":["local"]}`}}
					req, err := http.NewRequestWithContext(t.Context(), method, "http://"+address+path+"?"+query.Encode(), nil)
					if err != nil {
						t.Fatal(err)
					}
					response, err := http.DefaultClient.Do(req)
					if err != nil {
						t.Fatal(err)
					}
					defer response.Body.Close()
					if engineVersion != "6.0.0" {
						if response.StatusCode != http.StatusForbidden {
							t.Fatalf("status=%d, want 403 for old/unknown engine", response.StatusCode)
						}
						select {
						case <-seen:
							t.Fatal("restricted filter reached daemon")
						default:
						}
						return
					}
					if response.StatusCode != http.StatusOK {
						t.Fatalf("status=%d, want 200 for Podman6", response.StatusCode)
					}
					var upstreamQuery url.Values
					select {
					case upstreamQuery = <-seen:
					default:
						t.Fatal("modern request never reached daemon")
					}
					var filters map[string][]string
					if err := json.Unmarshal([]byte(upstreamQuery.Get("filters")), &filters); err != nil {
						t.Fatal(err)
					}
					for _, label := range []string{"com.sockguard.owner=job-123", "com.sockguard.visible=true"} {
						if !slices.Contains(filters["label"], label) {
							t.Fatalf("missing enforced label %s: %#v", label, filters)
						}
					}
					if !slices.Equal(filters["driver"], []string{"local"}) {
						t.Fatalf("client narrowing lost: %#v", filters)
					}
				})
			}
		}
	}
}
