package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v3/app/internal/apipath"
	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

// libpodContainerCreateCounterDaemon counts the native container creates that
// reach it. One that arrives has been accepted by the whole chain.
type libpodContainerCreateCounterDaemon struct {
	created atomic.Int32
}

func (d *libpodContainerCreateCounterDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	normPath := apipath.NormalizePath(r.URL.Path)
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && normPath == "/version":
		_ = json.NewEncoder(w).Encode(engineChainVersion(true))
	case r.Method == http.MethodPost && normPath == "/libpod/containers/create":
		_, _ = io.Copy(io.Discard, r.Body)
		d.created.Add(1)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"Id": "c1"})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// TestServeChainLibpodContainerCreateGatesStorageOptsAndRuntimeAnnotations
// sends SpecGenerator's storage_opts and its run.oci.* annotations through the
// production chain.
//
// storage_opts becomes the container's storage options
// (pkg/specgen/generate/container_create.go:530-531, WithStorageOpts) and
// annotations are "key-value options passed into the container runtime that
// can be used to trigger special behavior" (pkg/specgen/specgen.go:74-77).
// crun reads its behavior switches from the run.oci.* keys. Neither field was
// inspected, so with every option off a create carrying them reached the
// daemon (all three cases below were forwarded before the gates). Each case
// first runs with the options at their defaults, where it must be refused,
// then with its option opened, where it must reach the daemon.
//
// io.podman.annotations.* is not gated: Podman writes those keys itself as
// markers of options the create already carries, and podman-remote sends them
// on ordinary creates, so the last case pins that they pass.
func TestServeChainLibpodContainerCreateGatesStorageOptsAndRuntimeAnnotations(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		open       func(*config.LibpodContainerCreateRequestBodyConfig)
		wantReason string
	}{
		{
			name:       "storage_opts",
			body:       `{"image":"alpine","systemd":"false","storage_opts":{"size":"1T"}}`,
			open:       func(c *config.LibpodContainerCreateRequestBodyConfig) { c.AllowStorageOpts = true },
			wantReason: "libpod container create denied: storage_opts is not allowed (set allow_storage_opts: true)",
		},
		{
			name:       "run.oci annotation",
			body:       `{"image":"alpine","systemd":"false","annotations":{"run.oci.keep_original_groups":"1"}}`,
			open:       func(c *config.LibpodContainerCreateRequestBodyConfig) { c.AllowRuntimeAnnotations = true },
			wantReason: `libpod container create denied: runtime annotation "run.oci.keep_original_groups" is not allowed (set allow_runtime_annotations: true)`,
		},
		{
			name:       "run.oci annotation in another case",
			body:       `{"image":"alpine","systemd":"false","annotations":{"Run.OCI.Handler":"wasm"}}`,
			open:       func(c *config.LibpodContainerCreateRequestBodyConfig) { c.AllowRuntimeAnnotations = true },
			wantReason: `libpod container create denied: runtime annotation "Run.OCI.Handler" is not allowed (set allow_runtime_annotations: true)`,
		},
		{
			name:       "io.podman.annotations.cid-file",
			body:       `{"image":"alpine","systemd":"false","annotations":{"io.podman.annotations.cid-file":"/etc/passwd"}}`,
			open:       func(c *config.LibpodContainerCreateRequestBodyConfig) { c.AllowRuntimeAnnotations = true },
			wantReason: `libpod container create denied: runtime annotation "io.podman.annotations.cid-file" is not allowed`,
		},
		{
			name:       "io.podman.annotations.autoremove-image",
			body:       `{"image":"alpine","systemd":"false","annotations":{"io.podman.annotations.autoremove-image":"true"}}`,
			open:       func(c *config.LibpodContainerCreateRequestBodyConfig) { c.AllowRuntimeAnnotations = true },
			wantReason: `libpod container create denied: runtime annotation "io.podman.annotations.autoremove-image" is not allowed`,
		},
	}
	tests = append(tests, struct {
		name       string
		body       string
		open       func(*config.LibpodContainerCreateRequestBodyConfig)
		wantReason string
	}{
		name: "io.podman.annotations markers pass",
		body: `{"image":"alpine","systemd":"false","annotations":{"io.podman.annotations.userns":"private","io.podman.annotations.pids-limit":"100"}}`,
	})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, opened := range []bool{false, true} {
				if opened && tt.open == nil {
					continue
				}
				daemon := &libpodContainerCreateCounterDaemon{}
				addr := newEngineChain(t, "libpod-create-runtime", daemon, func(cfg *config.Config) {
					cfg.Response.DenyVerbosity = "verbose"
					if opened {
						tt.open(&cfg.RequestBody.LibpodContainerCreate)
					}
					cfg.Rules = []config.RuleConfig{
						{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/create"}, Action: "allow"},
						{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
					}
				})
				req, err := http.NewRequest(http.MethodPost, "http://"+addr+"/v5.8.6/libpod/containers/create", strings.NewReader(tt.body))
				if err != nil {
					t.Fatalf("new request: %v", err)
				}
				resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
				if err != nil {
					t.Fatalf("POST container create: %v", err)
				}
				respBody, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if tt.open == nil {
					if resp.StatusCode != http.StatusCreated || daemon.created.Load() != 1 {
						t.Errorf("status = %d, daemon creates = %d, want 201 and 1; body: %s", resp.StatusCode, daemon.created.Load(), respBody)
					}
					continue
				}
				if opened {
					if resp.StatusCode != http.StatusCreated || daemon.created.Load() != 1 {
						t.Errorf("opened: status = %d, daemon creates = %d, want 201 and 1; body: %s", resp.StatusCode, daemon.created.Load(), respBody)
					}
					continue
				}
				if resp.StatusCode != http.StatusForbidden || daemon.created.Load() != 0 {
					t.Errorf("default: status = %d, daemon creates = %d, want 403 and 0; body: %s", resp.StatusCode, daemon.created.Load(), respBody)
				}
				var denial struct {
					Reason string `json:"reason"`
				}
				if err := json.Unmarshal(respBody, &denial); err != nil || !strings.HasPrefix(denial.Reason, tt.wantReason) {
					t.Errorf("default: body = %s, want a reason starting with %q", respBody, tt.wantReason)
				}
			}
		})
	}
}
