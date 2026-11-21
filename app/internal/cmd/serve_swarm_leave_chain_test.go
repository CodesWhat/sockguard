package cmd

import (
	"io"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v2/app/internal/config"
)

// TestServeChainOwnerChecksSwarmLeaveAndUnlockKey sends the swarm state routes
// through the production chain with an exact allow rule and the insecure flags
// off. A swarm another owner holds must never see leave or the unlock key read.
func TestServeChainOwnerChecksSwarmLeaveAndUnlockKey(t *testing.T) {
	for _, tt := range []struct {
		name       string
		swarmOwner string
		wantStatus int
		wantHit    bool
	}{
		{name: "foreign swarm", swarmOwner: "job-999", wantStatus: http.StatusForbidden},
		{name: "unlabeled swarm", swarmOwner: "", wantStatus: http.StatusForbidden},
		{name: "own swarm", swarmOwner: "job-123", wantStatus: http.StatusOK, wantHit: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			socketPath := shortSocketPath(t, "chain-swarm-leave")
			_ = os.Remove(socketPath)

			var mu sync.Mutex
			hits := make(map[string]int)
			startUnixHTTPUpstream(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				hits[r.Method+" "+r.URL.Path]++
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/swarm":
					labels := `{}`
					if tt.swarmOwner != "" {
						labels = `{"com.sockguard.owner":"` + tt.swarmOwner + `"}`
					}
					_, _ = io.WriteString(w, `{"Spec":{"Labels":`+labels+`}}`)
				case "/v1.45/swarm/leave":
					w.WriteHeader(http.StatusOK)
				case "/v1.45/swarm/unlockkey":
					_, _ = io.WriteString(w, `{"UnlockKey":"SWMKEY-1-secret"}`)
				default:
					t.Errorf("unexpected upstream path %q", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			}))

			cfg := config.Defaults()
			cfg.Upstream.Socket = socketPath
			cfg.Health.Enabled = false
			cfg.Log.AccessLog = false
			cfg.Ownership.Owner = "job-123"
			cfg.Ownership.LabelKey = "com.sockguard.owner"
			cfg.Rules = []config.RuleConfig{
				{Match: config.MatchConfig{Method: http.MethodPost, Path: "/swarm/leave"}, Action: "allow"},
				{Match: config.MatchConfig{Method: http.MethodGet, Path: "/swarm/unlockkey"}, Action: "allow"},
				{Match: config.MatchConfig{Method: http.MethodGet, Path: "/swarm"}, Action: "allow"},
				{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "deny all"},
			}
			rules, err := compileRuleConfigsForTest(cfg.Rules)
			if err != nil {
				t.Fatalf("compile rules: %v", err)
			}
			handler := buildServeHandler(t, &cfg, newDiscardLogger(), nil, rules, newServeTestDeps())
			addr, _ := startProxyChainServer(t, handler)
			client := &http.Client{Timeout: 2 * time.Second}

			for _, req := range []struct {
				method, path string
			}{
				{http.MethodPost, "/v1.45/swarm/leave?force=1"},
				{http.MethodGet, "/v1.45/swarm/unlockkey"},
			} {
				httpReq, err := http.NewRequest(req.method, "http://"+addr+req.path, nil)
				if err != nil {
					t.Fatal(err)
				}
				resp, err := client.Do(httpReq)
				if err != nil {
					t.Fatalf("%s %s: %v", req.method, req.path, err)
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != tt.wantStatus {
					t.Errorf("%s %s status = %d, want %d", req.method, req.path, resp.StatusCode, tt.wantStatus)
				}
				path := req.path
				if i := len("/v1.45/swarm/leave"); len(path) > i && path[:i] == "/v1.45/swarm/leave" {
					path = path[:i]
				}
				mu.Lock()
				got := hits[req.method+" "+path] > 0
				mu.Unlock()
				if got != tt.wantHit {
					t.Errorf("%s %s reached the daemon = %v, want %v", req.method, path, got, tt.wantHit)
				}
			}
		})
	}
}
