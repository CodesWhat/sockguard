package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v2/app/internal/apipath"
	"github.com/codeswhat/sockguard/v2/app/internal/config"
)

const (
	imageNameChainOwnContainer    = "mine-ctr"
	imageNameChainVictimContainer = "theirs-ctr"
)

// imageNameChainDaemon is imageTagChainDaemon plus the other routes that give
// an image a name. Each route is a handler in its own test file, and a daemon
// serves the ones a test hands it, so every one of them shares one image
// store and one account of where a name lands.
//
// Where a name lands is the engine's call, and it differs by route:
//
//   - dockerd holds a name exactly as the client spelled it, on every route.
//   - Podman tags without a lookup on the routes that go through libimage's
//     Image.Tag: retag, import, and a build's tags. See landTagged.
//   - Podman resolves the name against local images first on a commit, through
//     libimage's ResolveName. See landResolved.
//
// Read from moby 28.5.1 and Podman 5.8.6, and the dockerd half confirmed
// against dockerd 29.5.2.
type imageNameChainDaemon struct {
	*imageTagChainDaemon
	// containers is the label set a container inspect answers with.
	containers map[string]map[string]string
	// routes are the name-assigning handlers this daemon serves. Each reports
	// whether the request was its own.
	routes []func(http.ResponseWriter, *http.Request, string) bool
	// created counts the images the daemon made, to name the next one.
	created int
	// legacyRepositories makes a load read the pre-1.10 `repositories` file
	// when the archive has no manifest.json, the way moby's classic image
	// store does up to 28.x. See serveLoad.
	legacyRepositories bool
}

func newImageNameChainDaemon() *imageNameChainDaemon {
	return &imageNameChainDaemon{
		imageTagChainDaemon: newImageTagChainDaemon(),
		containers: map[string]map[string]string{
			imageNameChainOwnContainer:    {imageTagChainLabelKey: imageTagChainOwner},
			imageNameChainVictimContainer: {imageTagChainLabelKey: "team-b"},
		},
	}
}

func (d *imageNameChainDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	normPath := apipath.NormalizePath(r.URL.Path)
	if name, ok := strings.CutPrefix(normPath, "/containers/"); ok && r.Method == http.MethodGet && strings.HasSuffix(name, "/json") {
		d.serveContainerInspect(w, r, strings.TrimSuffix(name, "/json"))
		return
	}
	for _, route := range d.routes {
		if route(w, r, normPath) {
			return
		}
	}
	d.imageTagChainDaemon.ServeHTTP(w, r)
}

func (d *imageNameChainDaemon) serveContainerInspect(w http.ResponseWriter, r *http.Request, name string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.requests = append(d.requests, r.Method+" "+apipath.NormalizePath(r.URL.Path))
	w.Header().Set("Content-Type", "application/json")
	labels, ok := d.containers[name]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"message":"No such container"}`)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"Id": name, "Config": map[string]any{"Labels": labels}})
}

// sawRequest reports whether the daemon saw method on normPath.
func (d *imageNameChainDaemon) sawRequest(method, normPath string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, request := range d.requests {
		if request == method+" "+normPath {
			return true
		}
	}
	return false
}

// record notes a request one of the routes took. The caller holds d.mu.
func (d *imageNameChainDaemon) record(r *http.Request, normPath string) {
	d.requests = append(d.requests, r.Method+" "+normPath)
}

// newImage adds an image carrying labels and returns its ID. The caller holds
// d.mu.
func (d *imageNameChainDaemon) newImage(labels map[string]string) string {
	d.created++
	id := fmt.Sprintf("sha256:new%d", d.created)
	d.labels[id] = labels
	return id
}

// podman reports whether the store is Podman-shaped. The caller holds d.mu.
func (d *imageNameChainDaemon) podman() bool {
	return d.shortNameAliases != nil
}

// param is the value the engine reads for key. dockerd reads the first value
// of the exact key from the parsed form (r.Form.Get). Podman decodes the query
// with gorilla/schema, which folds the key's case and keeps the last value.
// The caller holds d.mu.
func (d *imageNameChainDaemon) param(r *http.Request, key string) string {
	if !d.podman() {
		_ = r.ParseForm()
		return r.Form.Get(key)
	}
	value := ""
	for spelled, values := range r.URL.Query() {
		if strings.EqualFold(spelled, key) && len(values) > 0 {
			value = values[len(values)-1]
		}
	}
	return value
}

// imageNameChainRepoTag is moby's httputils.RepoTagReference: a tag carried in
// repo is kept unless tag replaces it, and "latest" when neither names one.
// Podman's handlers build repo + ":" + tag with the same default, which is the
// same string for every shape these tests send.
func imageNameChainRepoTag(repo, tag string) string {
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
	return name + ":" + tag
}

// imageNameChainName is the repository of a tag-qualified reference.
func imageNameChainName(ref string) string {
	if colon := strings.LastIndex(ref, ":"); colon > strings.LastIndex(ref, "/") {
		return ref[:colon]
	}
	return ref
}

// landTagged is the stored name a route that tags without a lookup of its own
// writes ref under. The caller holds d.mu.
//
// Podman runs the name through NormalizeToDockerHub. A request it reads as a
// native one returns from that untouched, and so does every request once
// compat_api_enforce_docker_hub is off. libimage's Image.Tag then stores a
// short name under localhost/. A compat request with the option at its default
// looks the name up first and tags whatever name the lookup found, or the
// Docker Hub one when nothing holds it.
func (d *imageNameChainDaemon) landTagged(r *http.Request, ref string) string {
	if !d.podman() {
		return ref
	}
	short := imageTagChainShortName(imageNameChainName(ref))
	if imageTagChainLibpodRequest(r) || d.enforceDockerHubOff {
		if short {
			return "localhost/" + ref
		}
		return ref
	}
	if held, ok := d.resolve(ref); ok {
		return held
	}
	if short {
		return imageTagChainDockerHubName(ref)
	}
	return ref
}

// landResolved is the stored name a commit writes ref under. The caller holds
// d.mu.
//
// Podman's commit hands the name to libimage's ResolveName, which looks it up
// locally before it normalizes: a name some image already holds resolves to
// that image's name, alias first, and only a name nothing holds is completed.
// The compat handler's NormalizeToDockerHub does the same lookup ahead of it,
// so the two agree on a held name and differ only in what an unheld short name
// becomes.
func (d *imageNameChainDaemon) landResolved(r *http.Request, ref string) string {
	if !d.podman() {
		return ref
	}
	if held, ok := d.resolve(ref); ok {
		return held
	}
	if !imageTagChainShortName(imageNameChainName(ref)) {
		return ref
	}
	if imageTagChainLibpodRequest(r) || d.enforceDockerHubOff {
		return "localhost/" + ref
	}
	return imageTagChainDockerHubName(ref)
}

// newImageNameChain builds the production chain for an owner-scoped client
// that may use every name-assigning route, in front of daemon.
func newImageNameChain(t *testing.T, daemon http.Handler, configure func(*config.Config)) string {
	t.Helper()
	return newImageTagChain(t, daemon, func(cfg *config.Config) {
		cfg.Rules = []config.RuleConfig{
			{Match: config.MatchConfig{Method: http.MethodPost, Path: "/commit"}, Action: "allow"},
			{Match: config.MatchConfig{Method: http.MethodPost, Path: "/build"}, Action: "allow"},
			{Match: config.MatchConfig{Method: http.MethodPost, Path: "/images/**"}, Action: "allow"},
			{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/commit"}, Action: "allow"},
			{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/build"}, Action: "allow"},
			{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/images/**"}, Action: "allow"},
			{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
		}
		cfg.RequestBody.Build.AllowRunInstructions = true
		cfg.RequestBody.ImagePull.AllowAllRegistries = true
		cfg.RequestBody.ImagePull.AllowImports = true
		cfg.RequestBody.ImageLoad.AllowAllRegistries = true
		if configure != nil {
			configure(cfg)
		}
	})
}

// imageNameChainStep is one name-assigning request in a sequence sent to the
// same daemon.
type imageNameChainStep struct {
	name        string
	target      string
	body        []byte
	contentType string
	// reference is the stored name the step is about, and wantImage the image
	// it has to point at once the request is answered. An empty wantImage
	// means the daemon made a new image and the name has to point at it.
	reference  string
	wantImage  string
	wantStatus int
}

// runImageNameChainStep sends one request and checks the status the client saw
// and where the reference points afterwards.
func runImageNameChainStep(t *testing.T, addr string, daemon *imageNameChainDaemon, step imageNameChainStep) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://"+addr+step.target, bytes.NewReader(step.body))
	if err != nil {
		t.Fatalf("%s: new request: %v", step.name, err)
	}
	if step.contentType != "" {
		req.Header.Set("Content-Type", step.contentType)
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("%s: POST %s: %v", step.name, step.target, err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != step.wantStatus {
		t.Errorf("%s: status = %d, want %d; body: %s", step.name, resp.StatusCode, step.wantStatus, body)
	}
	if step.reference == "" {
		return
	}
	got := daemon.nameTarget(step.reference)
	switch {
	case step.wantImage != "" && got != step.wantImage:
		t.Errorf("%s: %s points at %q after the request, want %q; daemon saw %v", step.name, step.reference, got, step.wantImage, daemon.requests)
	case step.wantImage == "" && !strings.HasPrefix(got, "sha256:new"):
		t.Errorf("%s: %s points at %q after the request, want the image the request made; daemon saw %v", step.name, step.reference, got, daemon.requests)
	}
}
