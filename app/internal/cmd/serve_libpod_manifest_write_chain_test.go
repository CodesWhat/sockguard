package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v2/app/internal/apipath"
	"github.com/codeswhat/sockguard/v2/app/internal/config"
	"github.com/codeswhat/sockguard/v2/app/internal/filter"
)

// libpodManifestChainDaemon is a Podman-shaped upstream holding A's and B's
// volumes. It answers the volume inspect owner isolation makes and records
// every other request, so a test can assert a refused write never arrived.
type libpodManifestChainDaemon struct {
	owners map[string]string

	mu   sync.Mutex
	seen []string
}

func (d *libpodManifestChainDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	normPath := apipath.NormalizePath(r.URL.Path)
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet && normPath == "/version" {
		_ = json.NewEncoder(w).Encode(engineChainVersion(true))
		return
	}
	// Owner isolation inspects through whichever spelling the route used, so
	// both the Docker-compat and the native volume inspect answer.
	if name, ok := strings.CutPrefix(normPath, "/volumes/"); r.Method == http.MethodGet && ok && !strings.Contains(name, "/") ||
		r.Method == http.MethodGet && strings.HasPrefix(normPath, "/libpod/volumes/") && strings.HasSuffix(normPath, "/json") {
		if strings.HasPrefix(normPath, "/libpod/") {
			name = strings.TrimSuffix(strings.TrimPrefix(normPath, "/libpod/volumes/"), "/json")
		}
		owner, ok := d.owners[name]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Name":   name,
			"Labels": map[string]string{"com.sockguard.owner": owner},
		})
		return
	}
	_, _ = io.Copy(io.Discard, r.Body)
	d.mu.Lock()
	d.seen = append(d.seen, r.Method+" "+normPath)
	d.mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]any{})
}

func (d *libpodManifestChainDaemon) requests() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.seen)
}

// TestServeChainLibpodManifestWritesUnderOwnerIsolation sends the libpod
// manifest list writes and volume rename through the production chain as
// owner team-a, with rules admitting every route and the body-blind
// acknowledgment set, against a daemon that holds team-a's and team-b's
// resources. None of the routes had an owner check, so each was forwarded for
// another owner's list or onto another owner's volume name.
func TestServeChainLibpodManifestWritesUnderOwnerIsolation(t *testing.T) {
	daemon := &libpodManifestChainDaemon{owners: map[string]string{"a-vol": "team-a", "b-vol": "team-b"}}
	addr := newEngineChain(t, "libpod-manifest-write", daemon, func(cfg *config.Config) {
		cfg.Response.DenyVerbosity = "verbose"
		cfg.Ownership.Owner = "team-a"
		cfg.InsecureAllowBodyBlindWrites = true
		cfg.Rules = []config.RuleConfig{
			{Match: config.MatchConfig{Method: "*", Path: "/libpod/manifests/**"}, Action: "allow"},
			{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/volumes/*/rename"}, Action: "allow"},
			{Match: config.MatchConfig{Method: http.MethodGet, Path: "/libpod/volumes/*/json"}, Action: "allow"},
			{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
		}
	})

	send := func(method, path, body string) (int, []byte) {
		t.Helper()
		req, err := http.NewRequest(method, "http://"+addr+path, strings.NewReader(body))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		respBody, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, respBody
	}

	const (
		manifestReason = filter.LibpodManifestWriteDenyReason
		renameReason   = filter.LibpodVolumeRenameDenyReason
	)
	attempts := []struct {
		name, method, path, body, wantReason string
	}{
		{"create over B list", http.MethodPost, "/v5.8.1/libpod/manifests/create?name=b-list:1&images=a-image:1", "", manifestReason},
		{"create A list", http.MethodPost, "/v5.8.1/libpod/manifests/create?name=a-list:1", "", manifestReason},
		{"modify B list (POST)", http.MethodPost, "/v5.8.1/libpod/manifests/b-list:1?operation=update", `{"images":["a-image:1"]}`, manifestReason},
		{"modify B list (PUT)", http.MethodPut, "/v5.8.1/libpod/manifests/b-list:1", `{"images":["a-image:1"],"operation":"update"}`, manifestReason},
		{"delete B list", http.MethodDelete, "/v5.8.1/libpod/manifests/b-list:1", "", manifestReason},
		{"add B image to A list", http.MethodPost, "/v5.8.1/libpod/manifests/a-list:1/add", `{"images":["b-image:1"]}`, manifestReason},
		{"add to B list", http.MethodPost, "/v5.8.1/libpod/manifests/b-list:1/add", `{"images":["a-image:1"]}`, manifestReason},
		{"registry push of B list", http.MethodPost, "/v5.8.1/libpod/manifests/b-list:1/registry/registry.example/stolen:1", "", manifestReason},
		{"push of B list", http.MethodPost, "/v5.8.1/libpod/manifests/b-list:1/push?destination=registry.example/stolen:1", "", manifestReason},
		{"unversioned delete of B list", http.MethodDelete, "/libpod/manifests/b-list:1", "", manifestReason},
		{"rename A volume onto B volume", http.MethodPost, "/v5.8.1/libpod/volumes/a-vol/rename?name=b-vol", "", renameReason},
		{"rename A volume by body", http.MethodPost, "/v5.8.1/libpod/volumes/a-vol/rename", `{"name":"b-vol"}`, renameReason},
		{"rename A volume to a free name", http.MethodPost, "/v5.8.1/libpod/volumes/a-vol/rename?name=a-renamed", "", renameReason},
	}
	for _, a := range attempts {
		t.Run(a.name, func(t *testing.T) {
			status, body := send(a.method, a.path, a.body)
			if status != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body: %s", status, body)
			}
			if !strings.Contains(string(body), a.wantReason) {
				t.Errorf("body = %s, want reason %s", body, a.wantReason)
			}
		})
	}
	if got := daemon.requests(); len(got) != 0 {
		t.Errorf("daemon saw requests from refused attempts: %v", got)
	}

	// Positive control: A's own volume read still reaches the daemon and B's
	// is refused, so the refusals above are the unscopeable-write check and
	// not a dead chain.
	if status, body := send(http.MethodGet, "/v5.8.1/libpod/volumes/a-vol/json", ""); status != http.StatusOK {
		t.Errorf("A reads own volume: status = %d, want 200; body: %s", status, body)
	}
	if status, body := send(http.MethodGet, "/v5.8.1/libpod/volumes/b-vol/json", ""); status != http.StatusForbidden && status != http.StatusNotFound {
		t.Errorf("A reads B volume: status = %d, want 403 or 404; body: %s", status, body)
	}
}
