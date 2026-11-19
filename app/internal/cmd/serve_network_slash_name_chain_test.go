package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v2/app/internal/config"
)

// TestServeChainOwnerChecksSlashBearingNetworkNames covers dockerd's
// /networks/{id:.*}/connect grammar: POST /networks/a/b/connect acts on the
// network "a/b", and the body's Container must be authorized too. Ownership
// used to check only "a" and never read the body.
func TestServeChainOwnerChecksSlashBearingNetworkNames(t *testing.T) {
	socketPath := shortSocketPath(t, "chain-net-slash")
	_ = os.Remove(socketPath)

	var mu sync.Mutex
	var acted []string
	networks := map[string]string{"a": "job-123", "a/b": "job-999", "mine": "job-123"}
	containers := map[string]string{"victim": "job-999", "mine": "job-123"}
	startUnixHTTPUpstream(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := strings.TrimPrefix(r.URL.Path, "/v1.45")
		if r.Method == http.MethodGet {
			var owner string
			var ok bool
			switch {
			case strings.HasPrefix(path, "/networks/"):
				owner, ok = networks[strings.TrimPrefix(path, "/networks/")]
			case strings.HasPrefix(path, "/containers/") && strings.HasSuffix(path, "/json"):
				owner, ok = containers[strings.TrimSuffix(strings.TrimPrefix(path, "/containers/"), "/json")]
			}
			if ok {
				_ = json.NewEncoder(w).Encode(map[string]any{"Id": "x", "Labels": map[string]string{"com.sockguard.owner": owner}, "Config": map[string]any{"Labels": map[string]string{"com.sockguard.owner": owner}}})
				return
			}
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"message":"not found"}`)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		acted = append(acted, r.Method+" "+path)
		w.WriteHeader(http.StatusNoContent)
	}))

	cfg := config.Defaults()
	cfg.Upstream.Socket = socketPath
	cfg.Health.Enabled = false
	cfg.Log.AccessLog = false
	cfg.Ownership.Owner = "job-123"
	cfg.Ownership.LabelKey = "com.sockguard.owner"
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/networks/**"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodDelete, Path: "/networks/**"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodGet, Path: "/networks/**"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "deny all"},
	}
	rules, err := compileRuleConfigsForTest(cfg.Rules)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	handler := buildServeHandler(t, &cfg, newDiscardLogger(), nil, rules, newServeTestDeps())
	addr, _ := startProxyChainServer(t, handler)
	client := &http.Client{Timeout: 2 * time.Second}

	do := func(method, path, body string) int {
		t.Helper()
		req, err := http.NewRequest(method, "http://"+addr+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	for _, req := range []struct{ method, path, body string }{
		{http.MethodPost, "/v1.45/networks/a/b/connect", `{"Container":"mine"}`},
		{http.MethodPost, "/networks/a/b/disconnect", `{"Container":"mine"}`},
		{http.MethodPost, "/networks/a%2Fb/connect", `{"Container":"mine"}`},
		{http.MethodPost, "/networks/a/connect", `{"Container":"victim"}`},
		{http.MethodDelete, "/networks/a/b", ""},
		{http.MethodGet, "/networks/a/b", ""},
	} {
		if status := do(req.method, req.path, req.body); status != http.StatusForbidden {
			t.Errorf("%s %s status = %d, want 403", req.method, req.path, status)
		}
	}
	mu.Lock()
	if len(acted) != 0 {
		t.Errorf("daemon acted on a foreign network or container: %v", acted)
	}
	mu.Unlock()

	if status := do(http.MethodPost, "/v1.45/networks/mine/connect", `{"Container":"mine"}`); status != http.StatusNoContent {
		t.Errorf("own network connect status = %d, want 204", status)
	}
}
