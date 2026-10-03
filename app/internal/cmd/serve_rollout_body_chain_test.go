package cmd

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/app/internal/apipath"
	"github.com/codeswhat/sockguard/app/internal/config"
)

// rolloutBodyChainDaemon answers the engine probe and keeps the body of every
// other request it is sent.
type rolloutBodyChainDaemon struct {
	mu     sync.Mutex
	bodies [][]byte
}

func (d *rolloutBodyChainDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet && apipath.NormalizePath(r.URL.Path) == "/version" {
		_ = json.NewEncoder(w).Encode(engineChainVersion(false))
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	d.mu.Lock()
	d.bodies = append(d.bodies, body)
	d.mu.Unlock()
	_, _ = io.WriteString(w, `{"stream":"done"}`)
}

func (d *rolloutBodyChainDaemon) received() [][]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([][]byte(nil), d.bodies...)
}

// rolloutBodyChainTar is a tar of name, body pairs, each a regular file with
// the given mode.
func rolloutBodyChainTar(t *testing.T, mode int64, entries ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := tar.NewWriter(&buf)
	for i := 0; i+1 < len(entries); i += 2 {
		name, body := entries[i], entries[i+1]
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatalf("write %s header: %v", name, err)
		}
		if _, err := io.WriteString(writer, body); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return buf.Bytes()
}

// TestServeChainRolloutForwardsTheBodyItInspected sends requests the filter
// refuses for what their body holds through the production chain, under a
// client profile in each rollout mode.
//
// Warn and audit forward a request the policy would deny. The inspectors that
// spool a body to a temp file to read it (a build context, an image load, a
// copy into a container, a plugin create) removed the file when they refused
// the request and left it holding the client's body, which the spool had
// already read to the end and closed. So a warn-mode build carrying a RUN
// reached the daemon with no body at all and was answered with a 502, instead
// of passing through the way the mode promises. A JSON body refused as too
// large went the same way, read up to the limit and closed.
func TestServeChainRolloutForwardsTheBodyItInspected(t *testing.T) {
	// The padding makes each body larger than any one read, so a body cut
	// short anywhere shows up as a mismatch.
	padding := strings.Repeat("sockguard rollout padding\n", 16<<10)
	oversized := []byte(`{"Image":"busybox","Labels":{"padding":"` + strings.Repeat("x", 1<<20) + `"}}`)

	tests := []struct {
		name        string
		method      string
		target      string
		body        []byte
		contentType string
		// chunked sends the body without a Content-Length.
		chunked bool
		// refusedWith is the status enforce answers with, or 0 for a request
		// the profile allows.
		refusedWith int
	}{
		{
			name:   "build with RUN",
			target: "/v1.45/build",
			body: rolloutBodyChainTar(t, 0o644,
				"Dockerfile", "FROM busybox\nRUN id\n",
				"assets/padding.txt", padding,
			),
			contentType: "application/x-tar",
			refusedWith: http.StatusForbidden,
		},
		{
			name:   "build without RUN",
			target: "/v1.45/build",
			body: rolloutBodyChainTar(t, 0o644,
				"Dockerfile", "FROM busybox\nCOPY . /app\n",
				"assets/padding.txt", padding,
			),
			contentType: "application/x-tar",
		},
		{
			name:   "image load naming a registry off the allowlist",
			target: "/v1.45/images/load",
			body: rolloutBodyChainTar(t, 0o644,
				"manifest.json", `[{"RepoTags":["elsewhere.example.com/app:latest"]}]`,
				"padding.txt", padding,
			),
			contentType: "application/x-tar",
			refusedWith: http.StatusForbidden,
		},
		{
			name:        "copy of a setuid file into a container",
			method:      http.MethodPut,
			target:      "/v1.45/containers/abc/archive?path=%2Ftmp",
			body:        rolloutBodyChainTar(t, 0o4755, "tool", padding),
			contentType: "application/x-tar",
			refusedWith: http.StatusForbidden,
		},
		{
			name:   "plugin create on the host network",
			target: "/v1.45/plugins/create?name=acme%2Fplugin",
			body: rolloutBodyChainTar(t, 0o644,
				"config.json", `{"Network":{"Type":"host"}}`,
				"rootfs/padding.txt", padding,
			),
			contentType: "application/x-tar",
			refusedWith: http.StatusForbidden,
		},
		{
			name:        "container create over the body limit",
			target:      "/v1.45/containers/create",
			body:        oversized,
			contentType: "application/json",
			refusedWith: http.StatusRequestEntityTooLarge,
		},
		{
			name:        "chunked container create over the body limit",
			target:      "/v1.45/containers/create",
			body:        oversized,
			contentType: "application/json",
			chunked:     true,
			refusedWith: http.StatusRequestEntityTooLarge,
		},
	}
	rules := []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/build"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/images/load"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPut, Path: "/containers/*/archive"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/plugins/create"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/create"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}
	for _, tt := range tests {
		for _, mode := range []string{"enforce", "warn", "audit"} {
			t.Run(tt.name+"/"+mode, func(t *testing.T) {
				spoolDir := t.TempDir()
				t.Setenv("TMPDIR", spoolDir)

				daemon := &rolloutBodyChainDaemon{}
				addr := newEngineChain(t, "rollout-body", daemon, func(cfg *config.Config) {
					cfg.Rules = rules
					cfg.Clients.Profiles = []config.ClientProfileConfig{{
						Name:  "rollout",
						Mode:  mode,
						Rules: rules,
						RequestBody: config.RequestBodyConfig{
							// RUN, setuid files and host-network plugins are
							// refused by the zero value.
							ImageLoad: config.ImageLoadRequestBodyConfig{AllowedRegistries: []string{"registry.example.com"}},
						},
					}}
					cfg.Clients.DefaultProfile = "rollout"
				})

				method := tt.method
				if method == "" {
					method = http.MethodPost
				}
				var body io.Reader = bytes.NewReader(tt.body)
				if tt.chunked {
					body = io.MultiReader(body)
				}
				req, err := http.NewRequest(method, "http://"+addr+tt.target, body)
				if err != nil {
					t.Fatalf("new request: %v", err)
				}
				req.Header.Set("Content-Type", tt.contentType)
				resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
				if err != nil {
					t.Fatalf("%s %s: %v", method, tt.target, err)
				}
				answer, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()

				wantStatus := http.StatusOK
				if mode == "enforce" && tt.refusedWith != 0 {
					wantStatus = tt.refusedWith
				}
				if resp.StatusCode != wantStatus {
					t.Errorf("status = %d, want %d; body: %s", resp.StatusCode, wantStatus, answer)
				}
				received := daemon.received()
				if wantStatus == http.StatusOK {
					if len(received) != 1 || !bytes.Equal(received[0], tt.body) {
						sizes := make([]int, len(received))
						for i, got := range received {
							sizes[i] = len(got)
						}
						t.Errorf("daemon received bodies of %v bytes, want the one %d byte body the client sent", sizes, len(tt.body))
					}
				} else if len(received) != 0 {
					t.Errorf("daemon received %d bodies, want the request stopped", len(received))
				}
				waitForEmptySpoolDir(t, spoolDir)
			})
		}
	}
}
