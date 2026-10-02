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

	"github.com/codeswhat/sockguard/app/internal/apipath"
	"github.com/codeswhat/sockguard/app/internal/config"
)

const (
	imageTagChainOwner    = "team-a"
	imageTagChainLabelKey = "com.sockguard.owner"

	imageTagChainOwnID     = "sha256:aaaa"
	imageTagChainVictimID  = "sha256:bbbb"
	imageTagChainUnownedID = "sha256:cccc"
)

// imageTagChainDaemon is a daemon-shaped image store: names point at image
// IDs, an inspect answers with the labels of whatever a name points at, and a
// tag moves the target name onto the source image no matter what it pointed
// at before.
//
// The tag handler reads its target the way dockerd's postImagesTag does
// (httputils.RepoTagReference): the first `repo` and `tag` values of the
// parsed form, a tag carried in `repo` kept unless `tag` replaces it, and
// "latest" when neither names one. Confirmed against dockerd 29.5.2. Podman
// registers its compat and libpod tag routes on one handler that builds
// repo + ":" + tag and moves the name the same way, and on the libpod route
// it stores a name with no registry under localhost/.
type imageTagChainDaemon struct {
	mu     sync.Mutex
	names  map[string]string
	labels map[string]map[string]string
	// requests is every request the daemon saw, as "METHOD normalized-path".
	requests []string
}

func newImageTagChainDaemon() *imageTagChainDaemon {
	return &imageTagChainDaemon{
		names: map[string]string{
			"mine:1":                              imageTagChainOwnID,
			"mine:stable":                         imageTagChainOwnID,
			"theirs/app:latest":                   imageTagChainVictimID,
			"theirs/app:v1":                       imageTagChainVictimID,
			"registry.example:5000/theirs/app:v1": imageTagChainVictimID,
			"registry.example:5000/theirs/app:latest": imageTagChainVictimID,
			"shared/base:latest":                      imageTagChainUnownedID,
		},
		labels: map[string]map[string]string{
			imageTagChainOwnID:     {imageTagChainLabelKey: imageTagChainOwner},
			imageTagChainVictimID:  {imageTagChainLabelKey: "team-b"},
			imageTagChainUnownedID: nil,
		},
	}
}

func (d *imageTagChainDaemon) nameTarget(name string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.names[name]
}

func (d *imageTagChainDaemon) sawTagCall() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.ContainsFunc(d.requests, func(request string) bool {
		return strings.HasPrefix(request, http.MethodPost+" ") && strings.HasSuffix(request, "/tag")
	})
}

func (d *imageTagChainDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	normPath := apipath.NormalizePath(r.URL.Path)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.requests = append(d.requests, r.Method+" "+normPath)
	w.Header().Set("Content-Type", "application/json")

	rest, isImage := strings.CutPrefix(strings.TrimPrefix(normPath, "/libpod"), "/images/")
	switch {
	case isImage && r.Method == http.MethodGet && strings.HasSuffix(rest, "/json"):
		id, ok := d.names[strings.TrimSuffix(rest, "/json")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"message":"No such image"}`)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Id":     id,
			"Config": map[string]any{"Labels": d.labels[id]},
		})
	case isImage && r.Method == http.MethodPost && strings.HasSuffix(rest, "/tag"):
		id, ok := d.names[strings.TrimSuffix(rest, "/tag")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"message":"No such image"}`)
			return
		}
		_ = r.ParseForm()
		repo, tag := r.Form.Get("repo"), r.Form.Get("tag")
		if repo == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		name, carried := repo, ""
		if colon := strings.LastIndex(repo, ":"); colon > strings.LastIndex(repo, "/") {
			name, carried = repo[:colon], repo[colon+1:]
		}
		switch {
		case tag != "":
		case carried != "":
			tag = carried
		default:
			tag = "latest"
		}
		if registry, _, _ := strings.Cut(name, "/"); strings.HasPrefix(normPath, "/libpod/") && !strings.ContainsAny(registry, ".:") && registry != "localhost" {
			name = "localhost/" + name
		}
		d.names[name+":"+tag] = id
		w.WriteHeader(http.StatusCreated)
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"message":"page not found"}`)
	}
}

func newImageTagChain(t *testing.T, daemon *imageTagChainDaemon, configure func(*config.Config)) string {
	t.Helper()

	socketPath := shortSocketPath(t, "tag-target")
	startUnixHTTPUpstream(t, socketPath, daemon)

	cfg := config.Defaults()
	cfg.Upstream.Socket = socketPath
	cfg.Health.Enabled = false
	cfg.Log.AccessLog = false
	cfg.Ownership.Owner = imageTagChainOwner
	cfg.Ownership.LabelKey = imageTagChainLabelKey
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/images/**"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/images/**"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}
	if configure != nil {
		configure(&cfg)
	}

	rules, err := compileRuleConfigsForTest(cfg.Rules)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	handler := buildServeHandler(t, &cfg, newDiscardLogger(), nil, rules, newServeTestDeps())
	addr, _ := startProxyChainServer(t, handler)
	return addr
}

// TestServeChainImageTagAuthorizesTheTargetReference sends image tag requests
// through the production handler chain to a daemon-shaped image store.
//
// The retag route names two images. The path names the source and the query
// names the reference to (re)point at it, and a daemon moves that reference
// off whatever image holds it. Owner isolation used to check the source alone,
// so a client could take a name away from another owner's image by tagging one
// of its own images with it. Every case asserts on the daemon's state: the
// name the request targets either still points where it did or was moved.
func TestServeChainImageTagAuthorizesTheTargetReference(t *testing.T) {
	denyUnowned := func(cfg *config.Config) { cfg.Ownership.AllowUnownedImages = false }

	tests := []struct {
		name      string
		configure func(*config.Config)
		// names replaces the daemon's default store when set.
		names  map[string]string
		target string
		// reference is the name the request aims at, and wantImage the image
		// it has to point at once the request is answered.
		reference  string
		wantImage  string
		wantStatus int
	}{
		{
			name:       "foreign target named by repo and tag",
			target:     "/v1.45/images/mine:1/tag?repo=theirs%2Fapp&tag=latest",
			reference:  "theirs/app:latest",
			wantImage:  imageTagChainVictimID,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "foreign target reached through the default tag",
			target:     "/v1.45/images/mine:1/tag?repo=theirs%2Fapp",
			reference:  "theirs/app:latest",
			wantImage:  imageTagChainVictimID,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "foreign target with the tag carried in repo",
			target:     "/v1.45/images/mine:1/tag?repo=theirs%2Fapp%3Av1",
			reference:  "theirs/app:v1",
			wantImage:  imageTagChainVictimID,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "foreign target on a registry with a port",
			target:     "/v1.45/images/mine:1/tag?repo=registry.example%3A5000%2Ftheirs%2Fapp&tag=v1",
			reference:  "registry.example:5000/theirs/app:v1",
			wantImage:  imageTagChainVictimID,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "registry port is not read as a tag",
			target:     "/v1.45/images/mine:1/tag?repo=registry.example%3A5000%2Ftheirs%2Fapp",
			reference:  "registry.example:5000/theirs/app:latest",
			wantImage:  imageTagChainVictimID,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "foreign target on the libpod tag route",
			target:     "/v5.0.0/libpod/images/mine:1/tag?repo=registry.example%3A5000%2Ftheirs%2Fapp&tag=v1",
			reference:  "registry.example:5000/theirs/app:v1",
			wantImage:  imageTagChainVictimID,
			wantStatus: http.StatusForbidden,
		},
		{
			// The store holds the victim's image under the localhost/ name
			// only, the way Podman keeps it. Nothing answers for the short
			// spelling, so the request is refused only if the check asks for
			// the name the tag will land on.
			name: "foreign short name on the libpod tag route is stored under localhost",
			names: map[string]string{
				"mine:1":                      imageTagChainOwnID,
				"localhost/theirs/app:latest": imageTagChainVictimID,
			},
			target:     "/v5.0.0/libpod/images/mine:1/tag?repo=theirs%2Fapp&tag=latest",
			reference:  "localhost/theirs/app:latest",
			wantImage:  imageTagChainVictimID,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "unlabeled target is refused once unowned images are",
			configure:  denyUnowned,
			target:     "/v1.45/images/mine:1/tag?repo=shared%2Fbase&tag=latest",
			reference:  "shared/base:latest",
			wantImage:  imageTagChainUnownedID,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "unlabeled target follows allow_unowned_images",
			target:     "/v1.45/images/mine:1/tag?repo=shared%2Fbase&tag=latest",
			reference:  "shared/base:latest",
			wantImage:  imageTagChainOwnID,
			wantStatus: http.StatusCreated,
		},
		{
			name:       "new reference is created",
			target:     "/v1.45/images/mine:1/tag?repo=mine%2Fnew&tag=v2",
			reference:  "mine/new:v2",
			wantImage:  imageTagChainOwnID,
			wantStatus: http.StatusCreated,
		},
		{
			name:       "caller moves its own reference",
			target:     "/v1.45/images/mine:1/tag?repo=mine&tag=stable",
			reference:  "mine:stable",
			wantImage:  imageTagChainOwnID,
			wantStatus: http.StatusCreated,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := newImageTagChainDaemon()
			if tt.names != nil {
				daemon.names = tt.names
			}
			addr := newImageTagChain(t, daemon, tt.configure)

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

			if got := daemon.nameTarget(tt.reference); got != tt.wantImage {
				t.Errorf("%s points at %s after the request, want %s; daemon saw %v", tt.reference, got, tt.wantImage, daemon.requests)
			}
			if resp.StatusCode != tt.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", resp.StatusCode, tt.wantStatus, body)
			}
			if wantForwarded := tt.wantStatus == http.StatusCreated; daemon.sawTagCall() != wantForwarded {
				t.Errorf("tag call reached the daemon = %v, want %v; daemon saw %v", daemon.sawTagCall(), wantForwarded, daemon.requests)
			}
		})
	}
}
