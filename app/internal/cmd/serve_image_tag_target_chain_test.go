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
	"github.com/codeswhat/sockguard/app/internal/upstreamflavor"
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
// repo + ":" + tag and moves the name the same way, and on a request it reads
// as a native one it stores a name with no registry under localhost/. See
// imageTagChainLibpodRequest for how it tells.
//
// It also answers GET /version with its engine's component name, which is all
// the upstream.flavor probe reads.
type imageTagChainDaemon struct {
	mu     sync.Mutex
	names  map[string]string
	labels map[string]map[string]string
	// shortNameAliases, when non-nil, makes the store Podman-shaped: every
	// stored name is registry-qualified and a name with no registry is looked
	// up the way resolve describes. Nil leaves it dockerd-shaped, where a
	// name is held exactly as the client spelled it.
	shortNameAliases map[string]string
	// enforceDockerHubOff is a Podman-shaped store running with
	// compat_api_enforce_docker_hub = false in containers.conf. A compat tag
	// request then skips the lookup the same way a native one does.
	enforceDockerHubOff bool
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

func (d *imageTagChainDaemon) tagCalls() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	calls := 0
	for _, request := range d.requests {
		if strings.HasPrefix(request, http.MethodPost+" ") && strings.HasSuffix(request, "/tag") {
			calls++
		}
	}
	return calls
}

func (d *imageTagChainDaemon) sawTagCall() bool {
	return d.tagCalls() > 0
}

// inspects is every image inspect the daemon answered, in order.
func (d *imageTagChainDaemon) inspects() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var inspects []string
	for _, request := range d.requests {
		if name, ok := strings.CutPrefix(request, http.MethodGet+" /images/"); ok && strings.HasSuffix(name, "/json") {
			inspects = append(inspects, strings.TrimSuffix(name, "/json"))
		}
	}
	return inspects
}

// resolve returns the stored name ref points at. The caller holds d.mu.
//
// A dockerd-shaped store matches the name as spelled. A Podman-shaped one
// follows libimage's LookupImage for a name with no registry: the
// registries.conf alias if the repository has one, then localhost/, then
// Docker Hub, with "latest" for a missing tag. Read from
// go.podman.io/common v0.67.1 and go.podman.io/image/v5 v5.39.2
// (shortnames.ResolveLocally).
func (d *imageTagChainDaemon) resolve(ref string) (string, bool) {
	if _, ok := d.names[ref]; ok {
		return ref, true
	}
	if d.shortNameAliases == nil {
		return "", false
	}
	repo, tag := ref, "latest"
	if colon := strings.LastIndex(ref, ":"); colon > strings.LastIndex(ref, "/") {
		repo, tag = ref[:colon], ref[colon+1:]
	}
	candidates := []string{repo}
	if imageTagChainShortName(repo) {
		candidates = []string{"localhost/" + repo, imageTagChainDockerHubName(repo)}
		if alias, ok := d.shortNameAliases[repo]; ok {
			candidates = append([]string{alias}, candidates...)
		}
	}
	for _, candidate := range candidates {
		if _, ok := d.names[candidate+":"+tag]; ok {
			return candidate + ":" + tag, true
		}
	}
	return "", false
}

// imageTagChainShortName reports whether name carries no registry.
func imageTagChainShortName(name string) bool {
	registry, _, _ := strings.Cut(name, "/")
	return !strings.ContainsAny(registry, ".:") && registry != "localhost"
}

func imageTagChainDockerHubName(name string) string {
	if !strings.Contains(name, "/") {
		return "docker.io/library/" + name
	}
	return "docker.io/" + name
}

// imageTagChainLibpodRequest is Podman's IsLibpodRequest
// (pkg/api/handlers/utils/apiutil, v5.8.6). It is how Podman decides whether
// a request is a native one, and it reads the request URL, not the route: the
// third "/"-separated piece is "libpod" in /v5.0.0/libpod/images/..., and it
// is the image name in an unversioned /images/{name}/tag.
func imageTagChainLibpodRequest(r *http.Request) bool {
	pieces := strings.Split(r.URL.String(), "/")
	return len(pieces) >= 3 && pieces[2] == "libpod"
}

func (d *imageTagChainDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	normPath := apipath.NormalizePath(r.URL.Path)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.requests = append(d.requests, r.Method+" "+normPath)
	w.Header().Set("Content-Type", "application/json")

	rest, isImage := strings.CutPrefix(strings.TrimPrefix(normPath, "/libpod"), "/images/")
	switch {
	case r.Method == http.MethodGet && normPath == "/version":
		// What the upstream.flavor probe reads: each engine names itself in
		// Components (Podman's compat/version.go, dockerd's SystemVersion).
		engine := "Engine"
		if d.shortNameAliases != nil {
			engine = "Podman Engine"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"Components": []map[string]string{{"Name": engine}}})
	case isImage && r.Method == http.MethodGet && strings.HasSuffix(rest, "/json"):
		name, ok := d.resolve(strings.TrimSuffix(rest, "/json"))
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"message":"No such image"}`)
			return
		}
		id := d.names[name]
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Id":     id,
			"Config": map[string]any{"Labels": d.labels[id]},
		})
	case isImage && r.Method == http.MethodPost && strings.HasSuffix(rest, "/tag"):
		source, ok := d.resolve(strings.TrimSuffix(rest, "/tag"))
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"message":"No such image"}`)
			return
		}
		id := d.names[source]
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
		// Podman runs the target through NormalizeToDockerHub. A native
		// request returns from it untouched, and so does every request once
		// compat_api_enforce_docker_hub is off. libimage's Image.Tag then
		// stores a short name under localhost/. A compat request with the
		// option at its default looks the name up first and tags whatever
		// name the lookup found, or the Docker Hub one when nothing holds it.
		// Read from Podman 5.8.6.
		target := name + ":" + tag
		switch {
		case imageTagChainLibpodRequest(r), d.enforceDockerHubOff:
			if imageTagChainShortName(name) {
				target = "localhost/" + target
			}
		case d.shortNameAliases != nil:
			if held, ok := d.resolve(target); ok {
				target = held
			} else if imageTagChainShortName(name) {
				target = imageTagChainDockerHubName(target)
			}
		}
		d.names[target] = id
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
	// The engine is resolved the way serve resolves it before it builds the
	// chain, with the production probe: upstream.flavor is "auto" unless a
	// case sets it, and the daemon names its own engine on GET /version.
	logger := newDiscardLogger()
	deps := newServeTestDeps()
	deps.detectUpstreamFlavor = upstreamflavor.Detect
	runtime, err := newServeRuntime(&cfg, logger, deps)
	if err != nil {
		t.Fatalf("newServeRuntime: %v", err)
	}
	if err := resolveUpstreamFlavorForRuntime(t.Context(), deps, runtime, &cfg, logger); err != nil {
		t.Fatalf("resolve upstream flavor: %v", err)
	}
	handler, teardown, _ := buildServeHandlerChainWithRuntime(serveHandlerBuild{
		Cfg:     &cfg,
		Logger:  logger,
		Rules:   rules,
		Deps:    deps,
		Runtime: runtime,
	})
	t.Cleanup(teardown)
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

// imageTagChainStep is one retag in a sequence sent to the same daemon.
type imageTagChainStep struct {
	name   string
	target string
	// reference is the stored name the step is about, and wantImage the image
	// it has to point at once the request is answered.
	reference  string
	wantImage  string
	wantStatus int
}

// runImageTagChainSteps sends steps in order and checks the daemon's state
// after each: where the reference points, the status the client saw, and how
// many tag calls reached the daemon so far.
func runImageTagChainSteps(t *testing.T, addr string, daemon *imageTagChainDaemon, steps []imageTagChainStep) {
	t.Helper()
	wantTagCalls := 0
	for _, step := range steps {
		req, err := http.NewRequest(http.MethodPost, "http://"+addr+step.target, nil)
		if err != nil {
			t.Fatalf("%s: new request: %v", step.name, err)
		}
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			t.Fatalf("%s: POST %s: %v", step.name, step.target, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		if step.wantStatus == http.StatusCreated {
			wantTagCalls++
		}
		if got := daemon.nameTarget(step.reference); got != step.wantImage {
			t.Errorf("%s: %s points at %s after the request, want %s", step.name, step.reference, got, step.wantImage)
		}
		if resp.StatusCode != step.wantStatus {
			t.Errorf("%s: status = %d, want %d; body: %s", step.name, resp.StatusCode, step.wantStatus, body)
		}
		if got := daemon.tagCalls(); got != wantTagCalls {
			t.Errorf("%s: tag calls that reached the daemon = %d, want %d", step.name, got, wantTagCalls)
		}
	}
}

// TestServeChainImageTagRefusesTheCompatPathPodmanReadsAsNative replays, against
// a Podman-shaped store, the three requests that took a localhost/ name away
// from another owner through the Docker-compatible route.
//
// The first two are ordinary retags onto names nothing holds, and stay
// allowed: one plants the caller's image under the name Podman's short-name
// alias for "nginx" resolves to, the other names the caller's image "libpod".
// The third retags that image on the unversioned path. Sockguard read
// POST /images/libpod/tag as a compat request and inspected "nginx:prod",
// which Podman answers alias-first with the planted image. Podman reads the
// same URL as a native request, because its third piece is "libpod", so it
// skips that lookup and moves localhost/nginx:prod. The path is refused.
func TestServeChainImageTagRefusesTheCompatPathPodmanReadsAsNative(t *testing.T) {
	daemon := newImageTagChainDaemon()
	daemon.names = map[string]string{
		"localhost/mine:1":     imageTagChainOwnID,
		"localhost/nginx:prod": imageTagChainVictimID,
	}
	daemon.shortNameAliases = map[string]string{"nginx": "docker.io/library/nginx"}
	addr := newImageTagChain(t, daemon, nil)

	runImageTagChainSteps(t, addr, daemon, []imageTagChainStep{
		{
			name:       "plant the name the alias resolves to",
			target:     "/v1.41/images/mine:1/tag?repo=docker.io%2Flibrary%2Fnginx&tag=prod",
			reference:  "docker.io/library/nginx:prod",
			wantImage:  imageTagChainOwnID,
			wantStatus: http.StatusCreated,
		},
		{
			name:       "name an image libpod",
			target:     "/v1.41/images/mine:1/tag?repo=docker.io%2Flibrary%2Flibpod",
			reference:  "docker.io/library/libpod:latest",
			wantImage:  imageTagChainOwnID,
			wantStatus: http.StatusCreated,
		},
		{
			name:       "retag it on the unversioned path",
			target:     "/images/libpod/tag?repo=nginx&tag=prod",
			reference:  "localhost/nginx:prod",
			wantImage:  imageTagChainVictimID,
			wantStatus: http.StatusForbidden,
		},
	})
}

// TestServeChainImageTagChecksTheLocalhostNameOnPodman replays, against a
// Podman-shaped store running with compat_api_enforce_docker_hub = false, the
// two requests that took a localhost/ name away from another owner on the
// ordinary versioned Docker-compatible route.
//
// With that option off Podman skips the lookup on every route and stores a
// `repo` that names no registry under localhost/. The first request plants the
// caller's image under the name the short-name alias for "nginx" resolves to,
// which nothing holds, and stays allowed. The second retags onto the short
// name. Sockguard inspected "nginx:prod", which Podman answers alias-first
// with the planted image, while the tag moved localhost/nginx:prod off the
// other owner's image. Sockguard cannot see the option, so on a Podman
// upstream it now inspects localhost/nginx:prod as well and the request is
// refused.
//
// A short name nobody holds under either reading is still created, and it
// lands under localhost/.
func TestServeChainImageTagChecksTheLocalhostNameOnPodman(t *testing.T) {
	// "auto" is the default and learns the engine from the daemon's GET
	// /version. "podman" is the operator saying so.
	for _, flavor := range []upstreamflavor.Flavor{upstreamflavor.Auto, upstreamflavor.Podman} {
		t.Run("upstream.flavor "+string(flavor), func(t *testing.T) {
			daemon := newImageTagChainDaemon()
			daemon.names = map[string]string{
				"localhost/mine:1":     imageTagChainOwnID,
				"localhost/nginx:prod": imageTagChainVictimID,
			}
			daemon.shortNameAliases = map[string]string{"nginx": "docker.io/library/nginx"}
			daemon.enforceDockerHubOff = true
			addr := newImageTagChain(t, daemon, func(cfg *config.Config) { cfg.Upstream.Flavor = string(flavor) })

			runImageTagChainSteps(t, addr, daemon, []imageTagChainStep{
				{
					name:       "plant the name the alias resolves to",
					target:     "/v1.41/images/mine:1/tag?repo=docker.io%2Flibrary%2Fnginx&tag=prod",
					reference:  "docker.io/library/nginx:prod",
					wantImage:  imageTagChainOwnID,
					wantStatus: http.StatusCreated,
				},
				{
					name:       "retag onto the short name",
					target:     "/v1.41/images/mine:1/tag?repo=nginx&tag=prod",
					reference:  "localhost/nginx:prod",
					wantImage:  imageTagChainVictimID,
					wantStatus: http.StatusForbidden,
				},
				{
					name:       "short name nothing holds",
					target:     "/v1.41/images/mine:1/tag?repo=mine%2Fnew&tag=v2",
					reference:  "localhost/mine/new:v2",
					wantImage:  imageTagChainOwnID,
					wantStatus: http.StatusCreated,
				},
			})

			// Source, then the target under the name as spelled and under
			// localhost/. A `repo` that names its registry has one reading
			// and is inspected once.
			want := []string{
				"mine:1", "docker.io/library/nginx:prod",
				"mine:1", "nginx:prod", "localhost/nginx:prod",
				"mine:1", "mine/new:v2", "localhost/mine/new:v2",
			}
			if got := daemon.inspects(); !slices.Equal(got, want) {
				t.Errorf("inspects the daemon answered = %v, want %v", got, want)
			}
		})
	}
}

// TestServeChainImageTagInspectsTheTargetOnceOnDockerd pins what the Podman
// check costs a dockerd upstream, which is nothing: a name means one reference
// there, so a `repo` that names no registry is inspected as spelled and
// localhost/ is never asked about.
func TestServeChainImageTagInspectsTheTargetOnceOnDockerd(t *testing.T) {
	for _, flavor := range []upstreamflavor.Flavor{upstreamflavor.Auto, upstreamflavor.Docker} {
		t.Run("upstream.flavor "+string(flavor), func(t *testing.T) {
			daemon := newImageTagChainDaemon()
			// On dockerd this is an image on a registry called localhost. It
			// is not the reference the request names.
			daemon.names["localhost/mine/new:v2"] = imageTagChainVictimID
			addr := newImageTagChain(t, daemon, func(cfg *config.Config) { cfg.Upstream.Flavor = string(flavor) })

			runImageTagChainSteps(t, addr, daemon, []imageTagChainStep{{
				name:       "short name nothing holds",
				target:     "/v1.45/images/mine:1/tag?repo=mine%2Fnew&tag=v2",
				reference:  "mine/new:v2",
				wantImage:  imageTagChainOwnID,
				wantStatus: http.StatusCreated,
			}})

			if got, want := daemon.inspects(), []string{"mine:1", "mine/new:v2"}; !slices.Equal(got, want) {
				t.Errorf("inspects the daemon answered = %v, want %v", got, want)
			}
			if got := daemon.nameTarget("localhost/mine/new:v2"); got != imageTagChainVictimID {
				t.Errorf("localhost/mine/new:v2 points at %s after the request, want %s", got, imageTagChainVictimID)
			}
		})
	}
}
