package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v3/app/internal/apipath"
	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

// presetCreateDaemon counts the container creates and starts that reach it. A
// request that arrives has been accepted by the whole chain.
type presetCreateDaemon struct {
	podman  bool
	created atomic.Int32
	started atomic.Int32
}

func (d *presetCreateDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	normPath := apipath.NormalizePath(r.URL.Path)
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && normPath == "/version":
		_ = json.NewEncoder(w).Encode(engineChainVersion(d.podman))
	case r.Method == http.MethodPost && normPath == "/containers/create":
		_, _ = io.Copy(io.Discard, r.Body)
		d.created.Add(1)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"Id": "c1"})
	case r.Method == http.MethodPost && strings.HasPrefix(normPath, "/containers/") && strings.HasSuffix(normPath, "/start"):
		_, _ = io.Copy(io.Discard, r.Body)
		d.started.Add(1)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// newPresetChain loads a shipped preset from app/configs and serves it through
// the production chain in front of daemon, so a test proves what a stock
// install does rather than what a hand-built config does.
func newPresetChain(t *testing.T, label, preset string, daemon http.Handler, tweak func(*config.Config)) string {
	t.Helper()
	loaded, err := config.Load(filepath.Join("..", "..", "configs", preset))
	if err != nil {
		t.Fatalf("load preset %s: %v", preset, err)
	}
	return newEngineChain(t, label, daemon, func(cfg *config.Config) {
		socket := cfg.Upstream.Socket
		*cfg = *loaded
		cfg.Upstream.Socket = socket
		cfg.Health.Enabled = false
		cfg.Log.AccessLog = false
		cfg.Response.DenyVerbosity = "verbose"
		if tweak != nil {
			tweak(cfg)
		}
	})
}

// presetChainPost sends one request and returns the status and body.
func presetChainPost(t *testing.T, addr, path, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://"+addr+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

// TestPresetChainDrydockRefusesWritableCgroups pins that the shipped drydock
// preset refuses the writable-cgroups SecurityOpt before it reaches dockerd.
func TestPresetChainDrydockRefusesWritableCgroups(t *testing.T) {
	for _, opt := range []string{"writable-cgroups", "writable-cgroups=true", "writable-cgroups:1", "Writable-Cgroups=T"} {
		t.Run(opt, func(t *testing.T) {
			daemon := &presetCreateDaemon{}
			addr := newPresetChain(t, "preset-wcg", "drydock.yaml", daemon, nil)
			for _, path := range []string{"/containers/create", "/v1.53/containers/create"} {
				status, body := presetChainPost(t, addr, path, `{"Image":"alpine","HostConfig":{"SecurityOpt":["`+opt+`"]}}`)
				if status != http.StatusForbidden || !strings.Contains(body, "writable-cgroups") {
					t.Errorf("%s: status = %d, body = %s, want 403 naming writable-cgroups", path, status, body)
				}
			}
			if daemon.created.Load() != 0 {
				t.Errorf("daemon creates = %d, want 0", daemon.created.Load())
			}
		})
	}
}
