package cmd

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/config"
)

// serveBuild is the build endpoint of both engines: POST /build, and Podman's
// POST /libpod/build, which runs on the same handler as its compat route. It
// makes an image carrying the `labels` parameter and points every `t` at it,
// no matter what those names pointed at before.
//
// dockerd reads every value of the exact key (r.Form["t"]), skips an empty
// one, and completes a name with no tag to :latest (the build backend's tag
// sanitizer). Podman decodes `t` with gorilla/schema, which folds the key's
// case. It hands the first tag to buildah as the output and tags the rest
// through libimage's Image.Tag. Buildah reads the output as a transport when
// the text before its first colon names one, and writes the image there
// instead of under the name as spelled: "containers-storage:foo" is the image
// "foo". Read from moby 28.5.1, Podman 5.8.6 and buildah 1.43.2, and the
// dockerd half confirmed against dockerd 29.5.2.
func (d *imageNameChainDaemon) serveBuild(w http.ResponseWriter, r *http.Request, normPath string) bool {
	if r.Method != http.MethodPost || (normPath != "/build" && normPath != "/libpod/build") {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.record(r, normPath)
	w.Header().Set("Content-Type", "application/json")

	labels := map[string]string{}
	_ = json.Unmarshal([]byte(d.param(r, "labels")), &labels)
	id := d.newImage(labels)

	var tags []string
	if d.podman() {
		for spelled, values := range r.URL.Query() {
			if strings.EqualFold(spelled, "t") {
				tags = values
			}
		}
	} else {
		_ = r.ParseForm()
		tags = r.Form["t"]
	}
	for i, tag := range tags {
		if tag == "" {
			continue
		}
		untouched := imageTagChainLibpodRequest(r) || d.enforceDockerHubOff
		if stored, ok := strings.CutPrefix(tag, "containers-storage:"); ok && d.podman() && untouched && i == 0 {
			tag = stored
		}
		d.names[d.landTagged(r, imageNameChainRepoTag(tag, ""))] = id
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"aux": map[string]string{"ID": id}})
	return true
}

func newImageBuildChainDaemon() *imageNameChainDaemon {
	daemon := newImageNameChainDaemon()
	daemon.routes = append(daemon.routes, daemon.serveBuild)
	return daemon
}

// imageBuildChainStep is a build request: the query names the images, and the
// body is a context the filter has no reason to open.
func imageBuildChainStep(name, target, reference, wantImage string, wantStatus int) imageNameChainStep {
	return imageNameChainStep{
		name:        name,
		target:      target,
		body:        []byte("FROM scratch\n"),
		contentType: "application/x-tar",
		reference:   reference,
		wantImage:   wantImage,
		wantStatus:  wantStatus,
	}
}

// TestServeChainBuildAuthorizesTheNamesItAssigns sends builds through the
// production handler chain to a daemon-shaped image store.
//
// A build names its image in `t`, as often as the client likes, and the daemon
// moves each of those names off whatever image holds it. Owner isolation
// stamped the new image and never read the names, so `docker build -t` onto a
// name another owner's image held took the name from it. Every case asserts on
// the daemon's state: the name the request targets either still points where
// it did or was moved.
func TestServeChainBuildAuthorizesTheNamesItAssigns(t *testing.T) {
	denyUnowned := func(cfg *config.Config) { cfg.Ownership.AllowUnownedImages = false }
	outputs := func(value string) string { return "&outputs=" + url.QueryEscape(value) }

	tests := []struct {
		name      string
		configure func(*config.Config)
		step      imageNameChainStep
	}{
		{name: "foreign name", step: imageBuildChainStep("", "/v1.45/build?t=theirs%2Fapp%3Alatest", "theirs/app:latest", imageTagChainVictimID, http.StatusForbidden)},
		{name: "foreign name through the default tag", step: imageBuildChainStep("", "/v1.45/build?t=theirs%2Fapp", "theirs/app:latest", imageTagChainVictimID, http.StatusForbidden)},
		{name: "foreign name behind a tag of the caller's own", step: imageBuildChainStep("", "/v1.45/build?t=mine%2Fnew&t=theirs%2Fapp%3Av1", "theirs/app:v1", imageTagChainVictimID, http.StatusForbidden)},
		{name: "foreign name on a registry with a port", step: imageBuildChainStep("", "/v1.45/build?t=registry.example%3A5000%2Ftheirs%2Fapp%3Av1", "registry.example:5000/theirs/app:v1", imageTagChainVictimID, http.StatusForbidden)},
		{name: "foreign name on the unversioned path", step: imageBuildChainStep("", "/build?t=theirs%2Fapp%3Av1", "theirs/app:v1", imageTagChainVictimID, http.StatusForbidden)},
		{
			// dockerd ignores this spelling and Podman reads it as `t`.
			name: "foreign name under another spelling of the key",
			step: imageBuildChainStep("", "/v1.45/build?T=theirs%2Fapp%3Av1", "theirs/app:v1", imageTagChainVictimID, http.StatusForbidden),
		},
		{
			// A BuildKit build names its image in the exporter's `name` when
			// the request carries no `t`.
			name: "foreign name in a BuildKit output",
			step: imageBuildChainStep("", "/v1.45/build?version=2"+outputs(`[{"Type":"image","Attrs":{"name":"theirs/app:v1"}}]`), "theirs/app:v1", imageTagChainVictimID, http.StatusForbidden),
		},
		{name: "unlabeled holder is refused once unowned images are", configure: denyUnowned, step: imageBuildChainStep("", "/v1.45/build?t=shared%2Fbase", "shared/base:latest", imageTagChainUnownedID, http.StatusForbidden)},
		{name: "unlabeled holder follows allow_unowned_images", step: imageBuildChainStep("", "/v1.45/build?t=shared%2Fbase", "shared/base:latest", "", http.StatusOK)},
		{name: "new name is created", step: imageBuildChainStep("", "/v1.45/build?t=mine%2Fnew%3Av2", "mine/new:v2", "", http.StatusOK)},
		{name: "caller rebuilds its own name", step: imageBuildChainStep("", "/v1.45/build?t=mine%3Astable&t=mine%2Fnew", "mine:stable", "", http.StatusOK)},
		{name: "build that names nothing", step: imageBuildChainStep("", "/v1.45/build", "", "", http.StatusOK)},
		{name: "output that names nothing", step: imageBuildChainStep("", "/v1.45/build?version=2"+outputs(`[{"Type":"local","Attrs":{}}]`), "", "", http.StatusOK)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := newImageBuildChainDaemon()
			addr := newImageNameChain(t, daemon, tt.configure)
			tt.step.name = tt.name

			runImageNameChainStep(t, addr, daemon, tt.step)

			wantForwarded := tt.step.wantStatus == http.StatusOK
			if got := daemon.sawRequest(http.MethodPost, "/build"); got != wantForwarded {
				t.Errorf("build reached the daemon = %v, want %v; daemon saw %v", got, wantForwarded, daemon.requests)
			}
		})
	}
}

// TestServeChainBuildStampsTheImageItNames checks the two halves together: an
// allowed build's image carries the caller's owner label, and the name points
// at it.
func TestServeChainBuildStampsTheImageItNames(t *testing.T) {
	daemon := newImageBuildChainDaemon()
	addr := newImageNameChain(t, daemon, nil)

	runImageNameChainStep(t, addr, daemon, imageBuildChainStep("stamped build", "/v1.45/build?t=mine%2Fnew", "mine/new:latest", "", http.StatusOK))

	daemon.mu.Lock()
	defer daemon.mu.Unlock()
	if got := daemon.labels[daemon.names["mine/new:latest"]][imageTagChainLabelKey]; got != imageTagChainOwner {
		t.Errorf("owner label on the built image = %q, want %q", got, imageTagChainOwner)
	}
}

// TestServeChainBuildChecksTheStoredNameOnPodman replays the build on a
// Podman-shaped store, where a tag that names no registry is stored under
// localhost/ on the native route, and on the compat one once
// compat_api_enforce_docker_hub is off.
func TestServeChainBuildChecksTheStoredNameOnPodman(t *testing.T) {
	tests := []struct {
		name string
		step imageNameChainStep
	}{
		{name: "native build onto a short name", step: imageBuildChainStep("", "/v5.0.0/libpod/build?t=nginx%3Aprod", "localhost/nginx:prod", imageTagChainVictimID, http.StatusForbidden)},
		{name: "compat build onto a short name", step: imageBuildChainStep("", "/v1.41/build?t=nginx%3Aprod", "localhost/nginx:prod", imageTagChainVictimID, http.StatusForbidden)},
		{
			// Buildah reads the output as the image "nginx:prod" in its
			// store, not as an image named "containers-storage".
			name: "native build onto a transport output",
			step: imageBuildChainStep("", "/v5.0.0/libpod/build?t=containers-storage%3Anginx%3Aprod", "localhost/nginx:prod", imageTagChainVictimID, http.StatusForbidden),
		},
		{name: "native build with a manifest list name", step: imageBuildChainStep("", "/v5.0.0/libpod/build?t=mine%2Fnew&manifest=nginx%3Aprod", "localhost/nginx:prod", imageTagChainVictimID, http.StatusForbidden)},
		{name: "native build onto a name nothing holds", step: imageBuildChainStep("", "/v5.0.0/libpod/build?t=mine%2Fnew%3Av2", "localhost/mine/new:v2", "", http.StatusOK)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := newImageBuildChainDaemon()
			daemon.names = map[string]string{
				"localhost/mine:1":             imageTagChainOwnID,
				"docker.io/library/nginx:prod": imageTagChainOwnID,
				"localhost/nginx:prod":         imageTagChainVictimID,
			}
			daemon.shortNameAliases = map[string]string{"nginx": "docker.io/library/nginx"}
			daemon.enforceDockerHubOff = true
			addr := newImageNameChain(t, daemon, nil)
			tt.step.name = tt.name

			runImageNameChainStep(t, addr, daemon, tt.step)
		})
	}
}
