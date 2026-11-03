package cmd

import (
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/apipath"
	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

// libpodRestoreChainDaemon is libpodCreateRefChainDaemon plus POST
// /libpod/containers/{name}/restore, which records the pod query parameter the
// restored container would join (Podman 5.8.1 handlers/libpod/containers.go
// Restore: `pod` goes straight to RestoreOptions.Pod).
type libpodRestoreChainDaemon struct {
	*libpodCreateRefChainDaemon
	rmu      sync.Mutex
	restored []string
}

func (d *libpodRestoreChainDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	norm := apipath.NormalizePath(r.URL.Path)
	if r.Method == http.MethodPost && strings.HasPrefix(norm, "/libpod/containers/") && strings.HasSuffix(norm, "/restore") {
		d.rmu.Lock()
		d.restored = append(d.restored, r.URL.Query().Get("pod"))
		d.rmu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
		return
	}
	d.libpodCreateRefChainDaemon.ServeHTTP(w, r)
}

// TestServeChainLibpodRestoreJoinsOnlyTheCallersPod sends restores of the
// caller's own container with a `pod` query through the production chain.
//
// Restore can join the restored container to a pod, and owner isolation
// checked the container in the path and nothing in the query, so team-a could
// put a container into team-b's pod. The pod is now looked up like the `pod`
// field of a create.
func TestServeChainLibpodRestoreJoinsOnlyTheCallersPod(t *testing.T) {
	tests := []struct {
		name         string
		query        string
		wantStatus   int
		wantRestored []string
	}{
		{"another owner's pod", "pod=theirs-pod", http.StatusForbidden, nil},
		{"another owner's pod by ID prefix", "pod=" + strings.Repeat("5", 12), http.StatusForbidden, nil},
		{"own pod", "pod=mine-pod", http.StatusOK, []string{"mine-pod"}},
		{"no pod", "keep=true", http.StatusOK, []string{""}},
		{"empty pod", "pod=", http.StatusOK, []string{""}},
		{"pod given twice", "pod=mine-pod&pod=theirs-pod", http.StatusForbidden, nil},
		{"pod in another spelling", "Pod=theirs-pod", http.StatusForbidden, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := &libpodRestoreChainDaemon{libpodCreateRefChainDaemon: newLibpodCreateRefChainDaemon()}
			addr := newEngineChain(t, "restore-pod", daemon, func(cfg *config.Config) {
				cfg.InsecureAllowBodyBlindWrites = true
				cfg.Ownership.Owner = "team-a"
				cfg.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/*/restore"}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
			})
			status, body := sendNamespaceChainRequest(t, "http://"+addr+"/v5.8.1/libpod/containers/mine-ctr/restore?"+tt.query, "")
			if status != tt.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", status, tt.wantStatus, body)
			}
			daemon.rmu.Lock()
			got := daemon.restored
			daemon.rmu.Unlock()
			if strings.Join(got, ",") != strings.Join(tt.wantRestored, ",") {
				t.Errorf("daemon restored with pod %q, want %q", got, tt.wantRestored)
			}
		})
	}
}
