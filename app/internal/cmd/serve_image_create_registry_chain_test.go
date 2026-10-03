package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/app/internal/apipath"
	"github.com/codeswhat/sockguard/app/internal/config"
)

// imageCreateChainDaemon is POST /images/create as each engine serves it. It
// records which operation a request turned into and what it named: the
// reference a pull fetched, or the source an import read.
//
// dockerd runs both operations in one handler (postImagesCreate). It parses
// the form, reads the first `fromImage`, and pulls when that is not empty. It
// only looks at `fromSrc` on the other branch, so a request carrying both is
// a pull and `fromSrc` is never read. Read from moby 28.5.1 and 29.5.2, and
// confirmed against dockerd 29.5.2: `?fromSrc=-&fromImage=localhost:1/x`
// answers with a failed registry request to localhost:1, in either order.
//
// Podman registers the path twice, once per operation, and gorilla/mux picks
// the handler by which exact key the query carries: `fromImage` is tried
// first and matches any value, the empty one included, then `fromSrc`. Each
// handler then decodes its own parameter with gorilla/schema, which folds the
// key's case and keeps the last value. See podmanSchemaScalar. Read from
// Podman 5.8.6 (pkg/api/server/register_images.go, compat.CreateImageFromImage
// and compat.CreateImageFromSrc).
type imageCreateChainDaemon struct {
	podman bool

	mu      sync.Mutex
	pulls   []string
	imports []string
}

func (d *imageCreateChainDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	normPath := apipath.NormalizePath(r.URL.Path)
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && normPath == "/version":
		_ = json.NewEncoder(w).Encode(engineChainVersion(d.podman))
	case r.Method == http.MethodPost && normPath == "/images/create":
		d.mu.Lock()
		defer d.mu.Unlock()
		pull, name, ok := d.operation(r)
		switch {
		case !ok:
			w.WriteHeader(http.StatusNotFound)
		case pull:
			d.pulls = append(d.pulls, name)
		default:
			d.imports = append(d.imports, name)
		}
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// operation reports which of the two operations the engine runs for r and
// the reference or source it runs it on. ok is false when no route matches.
func (d *imageCreateChainDaemon) operation(r *http.Request) (pull bool, name string, ok bool) {
	if !d.podman {
		_ = r.ParseForm()
		if image := r.Form.Get("fromImage"); image != "" {
			return true, image, true
		}
		return false, r.Form.Get("fromSrc"), true
	}
	query := r.URL.Query()
	if _, routed := query["fromImage"]; routed {
		return true, podmanSchemaScalar(query, "fromImage"), true
	}
	if _, routed := query["fromSrc"]; routed {
		return false, podmanSchemaScalar(query, "fromSrc"), true
	}
	return false, "", false
}

func (d *imageCreateChainDaemon) seen() (pulls, imports []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.pulls), slices.Clone(d.imports)
}

const imageCreateChainRegistry = "registry.internal.example"

func newImageCreateChain(t *testing.T, daemon *imageCreateChainDaemon, allowImports bool) string {
	t.Helper()
	return newEngineChain(t, "img-create", daemon, func(cfg *config.Config) {
		cfg.RequestBody.ImagePull.AllowImports = allowImports
		cfg.RequestBody.ImagePull.AllowedRegistries = []string{imageCreateChainRegistry}
		cfg.Rules = []config.RuleConfig{
			{Match: config.MatchConfig{Method: http.MethodPost, Path: "/images/create"}, Action: "allow"},
			{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
		}
	})
}

// TestServeChainImageCreateHoldsTheRegistryAllowlist sends image create
// requests through the production handler chain to a daemon that picks pull or
// import the way the engine does.
//
// The registry allowlist and allow_imports are two gates on one route, and the
// inspector answered the first one it met. It looked at `fromSrc` before
// `fromImage` and returned as soon as an import was allowed, so with
// allow_imports on, a request carrying both parameters was waved through as an
// import and pulled from whatever registry `fromImage` named. It also read
// each parameter as its first value under the exact key, which is how dockerd
// reads it and not how Podman does.
//
// Every case asserts on what reached the daemon: a pull only ever names the
// allowlisted registry, and an import only happens when imports are allowed.
func TestServeChainImageCreateHoldsTheRegistryAllowlist(t *testing.T) {
	const (
		allowed = imageCreateChainRegistry + "/team/app"
		foreign = "evil.example/x"
	)
	allowedQ, foreignQ := "registry.internal.example%2Fteam%2Fapp", "evil.example%2Fx"

	tests := []struct {
		name         string
		podman       bool
		allowImports bool
		target       string
		wantStatus   int
		wantPulls    []string
		wantImports  []string
	}{
		{
			name:         "import source ahead of a foreign pull",
			allowImports: true,
			target:       "/v1.45/images/create?fromSrc=-&fromImage=" + foreignQ + "&tag=latest",
			wantStatus:   http.StatusForbidden,
		},
		{
			name:         "foreign pull ahead of an import source",
			allowImports: true,
			target:       "/v1.45/images/create?fromImage=" + foreignQ + "&tag=latest&fromSrc=-",
			wantStatus:   http.StatusForbidden,
		},
		{
			name:         "import source ahead of a foreign pull on Podman",
			podman:       true,
			allowImports: true,
			target:       "/v1.41/images/create?fromSrc=-&fromImage=" + foreignQ + "&tag=latest",
			wantStatus:   http.StatusForbidden,
		},
		{
			// dockerd pulls the first value and Podman the last.
			name:       "foreign pull behind an allowlisted one on Podman",
			podman:     true,
			target:     "/v1.41/images/create?fromImage=" + allowedQ + "&fromImage=" + foreignQ,
			wantStatus: http.StatusForbidden,
		},
		{
			// dockerd ignores this spelling and Podman decodes it.
			name:       "foreign pull in another spelling on Podman",
			podman:     true,
			target:     "/v1.41/images/create?fromImage=" + allowedQ + "&FromImage=" + foreignQ,
			wantStatus: http.StatusForbidden,
		},
		{
			// The empty exact key routes Podman to its import handler and
			// the decoder fills the source from the other spelling.
			name:       "import source in another spelling on Podman",
			podman:     true,
			target:     "/v1.41/images/create?fromSrc=&FromSrc=http%3A%2F%2Fevil.example%2Frootfs.tar",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "import source behind an empty one on Podman",
			podman:     true,
			target:     "/v1.41/images/create?fromSrc=&fromSrc=http%3A%2F%2Fevil.example%2Frootfs.tar",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "import while imports are off",
			target:     "/v1.45/images/create?fromSrc=-&repo=team%2Fapp",
			wantStatus: http.StatusForbidden,
		},
		{
			name:         "allowlisted pull beside an import source",
			allowImports: true,
			target:       "/v1.45/images/create?fromSrc=-&fromImage=" + allowedQ + "&tag=latest",
			wantStatus:   http.StatusOK,
			wantPulls:    []string{allowed},
		},
		{
			name:       "allowlisted pull",
			target:     "/v1.45/images/create?fromImage=" + allowedQ + "&tag=latest",
			wantStatus: http.StatusOK,
			wantPulls:  []string{allowed},
		},
		{
			name:       "allowlisted pull on Podman",
			podman:     true,
			target:     "/v1.41/images/create?fromImage=" + allowedQ + "&tag=latest",
			wantStatus: http.StatusOK,
			wantPulls:  []string{allowed},
		},
		{
			name:         "import while imports are on",
			allowImports: true,
			target:       "/v1.45/images/create?fromSrc=-&repo=team%2Fapp",
			wantStatus:   http.StatusOK,
			wantImports:  []string{"-"},
		},
		{
			name:         "import on Podman while imports are on",
			podman:       true,
			allowImports: true,
			target:       "/v1.41/images/create?fromSrc=-&repo=team%2Fapp",
			wantStatus:   http.StatusOK,
			wantImports:  []string{"-"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := &imageCreateChainDaemon{podman: tt.podman}
			addr := newImageCreateChain(t, daemon, tt.allowImports)

			req, err := http.NewRequest(http.MethodPost, "http://"+addr+tt.target, nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
			if err != nil {
				t.Fatalf("POST %s: %v", tt.target, err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)

			pulls, imports := daemon.seen()
			if !slices.Equal(pulls, tt.wantPulls) {
				t.Errorf("daemon pulled %q, want %q", pulls, tt.wantPulls)
			}
			if !slices.Equal(imports, tt.wantImports) {
				t.Errorf("daemon imported from %q, want %q", imports, tt.wantImports)
			}
			if resp.StatusCode != tt.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", resp.StatusCode, tt.wantStatus, body)
			}
		})
	}
}
