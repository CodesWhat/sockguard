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

	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

// TestServeChainOwnerChecksSlashBearingContainerNames models a legacy link.
// The caller's own container "A" was created with a link to the victim, so
// dockerd answers to the alias "A/x" with the victim container. dockerd routes
// /containers/{name:.*}/<action>, so POST /containers/A/x/stop acts on the
// victim. Owner isolation used to check "A", the caller's own, and forward.
func TestServeChainOwnerChecksSlashBearingContainerNames(t *testing.T) {
	socketPath := shortSocketPath(t, "chain-slash-name")
	_ = os.Remove(socketPath)

	var mu sync.Mutex
	var acted []string
	var created int
	labels := map[string]map[string]string{
		"A":      {"com.sockguard.owner": "job-123"},
		"A/x":    {"com.sockguard.owner": "job-999"},
		"victim": {"com.sockguard.owner": "job-999"},
	}
	startUnixHTTPUpstream(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := strings.TrimPrefix(r.URL.Path, "/v1.45")
		if r.Method == http.MethodGet && strings.HasPrefix(path, "/containers/") && strings.HasSuffix(path, "/json") {
			name := strings.TrimSuffix(strings.TrimPrefix(path, "/containers/"), "/json")
			l, ok := labels[name]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				_, _ = io.WriteString(w, `{"message":"no such container"}`)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"Id": name, "Config": map[string]any{"Labels": l}})
			return
		}
		if r.Method == http.MethodGet && strings.HasPrefix(path, "/images/") {
			_ = json.NewEncoder(w).Encode(map[string]any{"Id": "sha256:1", "Config": map[string]any{"Labels": map[string]string{"com.sockguard.owner": "job-123"}}})
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if r.Method == http.MethodPost && path == "/containers/create" {
			created++
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"Id":"new"}`)
			return
		}
		acted = append(acted, r.Method+" "+path)
		w.WriteHeader(http.StatusNoContent)
	}))

	cfg := config.Defaults()
	cfg.Upstream.Socket = socketPath
	cfg.Health.Enabled = false
	cfg.Log.AccessLog = false
	cfg.Response.DenyVerbosity = "verbose"
	cfg.Ownership.Owner = "job-123"
	cfg.Ownership.LabelKey = "com.sockguard.owner"
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/**"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodDelete, Path: "/containers/**"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "deny all"},
	}
	rules, err := compileRuleConfigsForTest(cfg.Rules)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	handler := buildServeHandler(t, &cfg, newDiscardLogger(), nil, rules, newServeTestDeps())
	addr, _ := startProxyChainServer(t, handler)
	client := &http.Client{Timeout: 2 * time.Second}

	doBody := func(method, path, body string) (int, string) {
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
		out, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, string(out)
	}
	do := func(method, path, body string) int {
		t.Helper()
		status, _ := doBody(method, path, body)
		return status
	}

	for _, req := range []struct{ method, path string }{
		{http.MethodPost, "/v1.45/containers/A/x/stop"},
		{http.MethodPost, "/containers/A/x/kill"},
		{http.MethodPost, "/containers/A%2Fx/restart"},
		{http.MethodPost, "/containers/A/x/pause"},
		{http.MethodDelete, "/v1.45/containers/A/x?force=1"},
	} {
		if status := do(req.method, req.path, ""); status != http.StatusForbidden {
			t.Errorf("%s %s status = %d, want 403", req.method, req.path, status)
		}
	}
	mu.Lock()
	if len(acted) != 0 {
		t.Errorf("daemon acted on the victim through its alias: %v", acted)
	}
	mu.Unlock()

	// Ordinary single-segment routes are unchanged.
	if status := do(http.MethodPost, "/v1.45/containers/A/stop", ""); status != http.StatusNoContent {
		t.Errorf("own container stop status = %d, want 204", status)
	}
	if status := do(http.MethodPost, "/containers/victim/stop", ""); status != http.StatusForbidden {
		t.Errorf("victim stop status = %d, want 403", status)
	}

	// A create that links the victim is refused before it reaches the daemon.
	status, body := doBody(http.MethodPost, "/v1.45/containers/create", `{"Image":"alpine","HostConfig":{"Links":["victim:x"]}}`)
	if status != http.StatusForbidden {
		t.Errorf("create linking a foreign container status = %d, want 403", status)
	}
	// The filter's container-create body inspector refuses HostConfig.Links
	// outright, ahead of ownership's own check of the link sources, so this
	// denial names the filter layer. A 403 from ownership would carry a
	// different reason and would mean the filter refusal had regressed.
	if !strings.Contains(body, "legacy container links (HostConfig.Links) are not allowed") {
		t.Errorf("create linking a foreign container body = %s, want the filter's HostConfig.Links refusal", body)
	}
	mu.Lock()
	defer mu.Unlock()
	if created != 0 {
		t.Errorf("daemon created %d containers, want 0", created)
	}
	if len(acted) != 1 || acted[0] != "POST /containers/A/stop" {
		t.Errorf("daemon actions = %v, want only the own-container stop", acted)
	}
}
