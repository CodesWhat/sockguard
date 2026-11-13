package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"sync"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/apipath"
	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

// libpodUpdateCgroupDaemon is a Podman whose container has a 256 MiB memory
// limit and whose libpod update applies the body the way the OCI runtime
// does: the typed resources first, then the cgroup v2 `unified` map written
// last, key by key, straight to the cgroup file (runc libcontainer/cgroups/fs2
// Manager.Set calls setUnified after setMemory, setCPU and setPids). So
// {"unified":{"memory.max":"max"}} leaves the container with no memory limit
// whatever "memory.limit" said.
type libpodUpdateCgroupDaemon struct {
	mu     sync.Mutex
	memory int64
	calls  int
}

func (d *libpodUpdateCgroupDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	norm := apipath.NormalizePath(r.URL.Path)
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case r.Method == http.MethodGet && norm == "/version":
		_ = json.NewEncoder(w).Encode(engineChainVersion(true))
	case r.Method == http.MethodGet:
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Id":         "sha256:1",
			"Config":     map[string]any{"Labels": map[string]string{}},
			"HostConfig": map[string]any{"Memory": d.memory},
		})
	case r.Method == http.MethodPost && norm == "/libpod/containers/c/update":
		var body struct {
			Memory *struct {
				Limit *int64 `json:"limit"`
			} `json:"memory"`
			Unified map[string]string `json:"unified"`
		}
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		d.calls++
		if body.Memory != nil && body.Memory.Limit != nil {
			d.memory = *body.Memory.Limit
		}
		if v, ok := body.Unified["memory.max"]; ok {
			if v == "max" {
				d.memory = 0
			} else if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				d.memory = n
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{}`)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (d *libpodUpdateCgroupDaemon) state() (int64, int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.memory, d.calls
}

// TestServeChainLibpodUpdateUnifiedCannotClearRequiredMemoryLimit sends libpod
// container updates through the production chain with require_memory_limit on
// and checks the memory limit the container ends up with.
//
// The guard overlaid only `memory.limit`, `cpu` and `pids` onto the container's
// current state, so a body that set a limit and then cleared it with the
// `unified` cgroup map satisfied require_memory_limit while leaving the
// container unlimited.
func TestServeChainLibpodUpdateUnifiedCannotClearRequiredMemoryLimit(t *testing.T) {
	const limit = 268435456
	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantMemory int64
	}{
		{name: "limit alone", body: `{"memory":{"limit":536870912}}`, wantStatus: http.StatusOK, wantMemory: 536870912},
		{name: "limit then cleared by unified memory.max", body: `{"memory":{"limit":536870912},"unified":{"memory.max":"max"}}`, wantStatus: http.StatusForbidden, wantMemory: limit},
		{name: "cleared by unified alone", body: `{"unified":{"memory.max":"max"}}`, wantStatus: http.StatusForbidden, wantMemory: limit},
		{name: "unified memory.high only", body: `{"unified":{"memory.high":"134217728"}}`, wantStatus: http.StatusOK, wantMemory: limit},
	}
	rules := []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/*/update"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := &libpodUpdateCgroupDaemon{memory: limit}
			addr := newEngineChainWithLogger(t, "libpod-unified", daemon, newDiscardLogger(), func(cfg *config.Config) {
				cfg.Rules = rules
				cfg.RequestBody.ContainerUpdate.AllowResourceUpdates = true
				cfg.RequestBody.ContainerUpdate.RequireMemoryLimit = true
			})
			status, answer := sendNamespaceChainRequest(t, "http://"+addr+"/v1.45/libpod/containers/c/update", tt.body)
			if status != tt.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", status, tt.wantStatus, answer)
			}
			if memory, _ := daemon.state(); memory != tt.wantMemory {
				t.Errorf("container memory limit = %d, want %d", memory, tt.wantMemory)
			}
		})
	}
}
