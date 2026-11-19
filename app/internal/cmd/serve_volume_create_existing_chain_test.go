package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

// TestServeChainVolumeCreateDoesNotLeakAnExistingForeignVolume models the
// daemon's create: a name that is taken answers 201 with the stored volume,
// Labels and Options included. The create must be refused before the daemon is
// asked when the preflight sees a foreign or unlabeled volume, and the response
// must be refused when a concurrent create made the volume after the preflight.
func TestServeChainVolumeCreateDoesNotLeakAnExistingForeignVolume(t *testing.T) {
	const secret = "password=hunter2"
	tests := []struct {
		name         string
		volume       string
		wantStatus   int
		wantReaches  bool
		wantNoSecret bool
	}{
		{name: "foreign volume", volume: "theirs", wantStatus: http.StatusForbidden},
		{name: "unlabeled volume", volume: "shared", wantStatus: http.StatusForbidden},
		{name: "same owner volume", volume: "mine", wantStatus: http.StatusCreated, wantReaches: true},
		{name: "new volume", volume: "fresh", wantStatus: http.StatusCreated, wantReaches: true},
		// Preflight 404s, then another owner creates it before ours lands.
		{name: "volume created concurrently by another owner", volume: "racing", wantStatus: http.StatusForbidden, wantReaches: true, wantNoSecret: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			socketPath := shortSocketPath(t, "chain-volume-create")
			_ = os.Remove(socketPath)

			var mu sync.Mutex
			createReached := false
			existing := map[string]map[string]string{
				"theirs": {"com.sockguard.owner": "job-999"},
				"shared": {},
				"mine":   {"com.sockguard.owner": "job-123"},
			}
			startUnixHTTPUpstream(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/volumes/"):
					name := strings.TrimPrefix(r.URL.Path, "/volumes/")
					labels, ok := existing[name]
					if !ok {
						w.WriteHeader(http.StatusNotFound)
						_, _ = io.WriteString(w, `{"message":"no such volume"}`)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"Name": name, "Labels": labels})
				case r.Method == http.MethodPost && r.URL.Path == "/v1.45/volumes/create":
					mu.Lock()
					createReached = true
					mu.Unlock()
					var req struct {
						Name   string
						Labels map[string]string
					}
					_ = json.NewDecoder(r.Body).Decode(&req)
					labels, ok := existing[req.Name]
					if !ok {
						labels = req.Labels
						if req.Name == "racing" {
							labels = map[string]string{"com.sockguard.owner": "job-999"}
						}
					}
					w.WriteHeader(http.StatusCreated)
					_ = json.NewEncoder(w).Encode(map[string]any{
						"Name": req.Name, "Driver": "local", "Labels": labels,
						"Mountpoint": "/mnt/host/path", "Options": map[string]string{"o": secret},
					})
				default:
					t.Errorf("unexpected upstream request %s %s", r.Method, r.URL.Path)
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
				{Match: config.MatchConfig{Method: http.MethodPost, Path: "/volumes/create"}, Action: "allow"},
				{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "deny all"},
			}
			rules, err := compileRuleConfigsForTest(cfg.Rules)
			if err != nil {
				t.Fatalf("compile rules: %v", err)
			}
			handler := buildServeHandler(t, &cfg, newDiscardLogger(), nil, rules, newServeTestDeps())
			addr, _ := startProxyChainServer(t, handler)

			body := `{"Name":` + string(mustJSON(t, tt.volume)) + `}`
			req, err := http.NewRequest(http.MethodPost, (&url.URL{Scheme: "http", Host: addr, Path: "/v1.45/volumes/create"}).String(), strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
			if err != nil {
				t.Fatalf("create: %v", err)
			}
			got, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", resp.StatusCode, tt.wantStatus, got)
			}
			mu.Lock()
			reached := createReached
			mu.Unlock()
			if reached != tt.wantReaches {
				t.Errorf("create reached the daemon = %v, want %v", reached, tt.wantReaches)
			}
			if strings.Contains(string(got), secret) && (tt.wantNoSecret || resp.StatusCode == http.StatusForbidden) {
				t.Errorf("foreign volume Options reached the client: %s", got)
			}
			if strings.Contains(string(got), "/mnt/host/path") {
				t.Errorf("Mountpoint was not redacted: %s", got)
			}
		})
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
