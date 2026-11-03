package cmd

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/apipath"
	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

// tmpfsChainDaemon answers GET /version as Docker or Podman and counts the
// write requests that reach it, whatever the route. A tmpfs gate is judged by
// whether the create got through, so the daemon needs no model of what the
// mount would do.
type tmpfsChainDaemon struct {
	podman  bool
	reached atomic.Int32
}

func (d *tmpfsChainDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet && apipath.NormalizePath(r.URL.Path) == "/version" {
		_ = json.NewEncoder(w).Encode(engineChainVersion(d.podman))
		return
	}
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	d.reached.Add(1)
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"Id": "c1", "Name": "v1"})
}

// tmpfsChainCase is one request through the production chain.
type tmpfsChainCase struct {
	name       string
	podman     bool
	configure  func(*config.RequestBodyConfig)
	method     string // default POST
	path       string
	body       string
	wantReach  bool
	wantReason string // substring of the denial reason; empty means allowed
}

func runTmpfsChainCases(t *testing.T, tests []tmpfsChainCase) {
	t.Helper()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := &tmpfsChainDaemon{podman: tt.podman}
			addr := newEngineChain(t, "tmpfs", daemon, func(cfg *config.Config) {
				cfg.Response.DenyVerbosity = "verbose"
				cfg.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "allow"},
				}
				if tt.configure != nil {
					tt.configure(&cfg.RequestBody)
				}
			})
			method := tt.method
			if method == "" {
				method = http.MethodPost
			}
			req, err := http.NewRequest(method, "http://"+addr+tt.path, strings.NewReader(tt.body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			var denial struct {
				Reason string `json:"reason"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&denial)

			if got := daemon.reached.Load() > 0; got != tt.wantReach {
				t.Errorf("reached daemon = %t, want %t (status %d, reason %q)", got, tt.wantReach, resp.StatusCode, denial.Reason)
			}
			if tt.wantReason == "" {
				if resp.StatusCode != http.StatusCreated {
					t.Errorf("status = %d, want 201 (reason %q)", resp.StatusCode, denial.Reason)
				}
				return
			}
			if resp.StatusCode != http.StatusForbidden || !strings.Contains(denial.Reason, tt.wantReason) {
				t.Errorf("status = %d reason = %q, want 403 containing %q", resp.StatusCode, denial.Reason, tt.wantReason)
			}
		})
	}
}
