package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/apipath"
	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

// libpodVolumeOptChainDaemon is a Podman whose container create makes every
// named volume the body names that doesn't exist, the way libpod/runtime_ctr.go
// does (Podman 5.8.1): an option of a volumes[] entry that starts with
// "volume-opt" is split on its first two "=" into a driver option of the new
// volume, and the volume is created with them. It records the driver options
// of each volume it made.
type libpodVolumeOptChainDaemon struct {
	mu      sync.Mutex
	created []map[string]string
}

func (d *libpodVolumeOptChainDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	norm := apipath.NormalizePath(r.URL.Path)
	switch {
	case r.Method == http.MethodGet && norm == "/version":
		_ = json.NewEncoder(w).Encode(engineChainVersion(true))
	case r.Method == http.MethodPost && norm == "/libpod/containers/create":
		var body struct {
			Volumes []struct {
				Name    string   `json:"Name"`
				Options []string `json:"Options"`
			} `json:"Volumes"`
		}
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		for _, volume := range body.Volumes {
			driverOpts := map[string]string{}
			for _, option := range volume.Options {
				if !strings.HasPrefix(option, "volume-opt") {
					continue
				}
				_, rest, _ := strings.Cut(option, "=")
				key, value, ok := strings.Cut(rest, "=")
				if !ok {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				driverOpts[key] = value
			}
			d.mu.Lock()
			d.created = append(d.created, driverOpts)
			d.mu.Unlock()
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"Id":"c1"}`)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (d *libpodVolumeOptChainDaemon) volumes() []map[string]string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.created)
}

// TestServeChainLibpodVolumeOptCannotBindAHostPath sends libpod container
// creates whose volumes[] entries carry "volume-opt=" options through the
// production chain, with owner isolation off.
//
// Podman creates a named volume the container names and nothing holds, and
// hands it the entry's volume-opt options as driver options. On the local
// driver those are mount options, so "volume-opt=o=bind" with
// "volume-opt=device=/etc" is a bind mount of the host's /etc. The volume
// create endpoint holds those options to allowed_bind_mounts, and a container
// create reached the same host path with no check. It now holds them to the
// same allowlist.
func TestServeChainLibpodVolumeOptCannotBindAHostPath(t *testing.T) {
	bind := func(device string) string {
		return `"Options":["volume-opt=type=none","volume-opt=o=bind","volume-opt=device=` + device + `"]`
	}
	tests := []struct {
		name    string
		allowed []string
		options string
		want    bool
	}{
		{"bind of a host path", nil, bind("/etc"), false},
		{"bind of a host path outside the allowlist", []string{"/srv/data"}, bind("/etc"), false},
		{"bind of an allowlisted host path", []string{"/srv/data"}, bind("/srv/data/app"), true},
		{"traversal out of the allowlist", []string{"/srv/data"}, bind("/srv/data/../../etc"), false},
		{"device without a bind option", []string{"/srv/data"}, `"Options":["volume-opt=type=none","volume-opt=device=/etc"]`, false},
		{"option key with a suffix after volume-opt", nil, `"Options":["volume-optx=o=bind","volume-optx=device=/etc","volume-optx=type=none"]`, false},
		{"driver option that names no host path", nil, `"Options":["volume-opt=size=64m"]`, true},
		{"no volume-opt options", nil, `"Options":["ro"]`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := &libpodVolumeOptChainDaemon{}
			addr := newEngineChain(t, "volume-opt", daemon, func(cfg *config.Config) {
				cfg.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/create"}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
				cfg.RequestBody.LibpodContainerCreate.AllowedBindMounts = tt.allowed
			})
			body := `{"image":"alpine","systemd":"false","Volumes":[{"Name":"fresh","Dest":"/data",` + tt.options + `}]}`
			status, answer := sendNamespaceChainRequest(t, "http://"+addr+"/v5.8.6/libpod/containers/create", body)
			wantStatus := http.StatusForbidden
			if tt.want {
				wantStatus = http.StatusCreated
			}
			if status != wantStatus {
				t.Errorf("status = %d, want %d; body: %s", status, wantStatus, answer)
			}
			if got := len(daemon.volumes()); (got == 1) != tt.want {
				t.Errorf("daemon created %d volumes: %v", got, daemon.volumes())
			}
		})
	}
}
