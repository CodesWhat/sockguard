package cmd

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/config"
)

// serveImport is the image import of both engines: POST /images/create with
// no `fromImage`, and Podman's native POST /libpod/images/import. It makes an
// unlabeled image from the body and points the name the request carries at
// it, no matter what that name pointed at before.
//
// dockerd names the image with httputils.RepoTagReference over `repo` and
// `tag`. Podman's compat handler builds the same reference and its native one
// takes it whole in `reference`, and both tag through libimage's Image.Tag.
// Read from moby 28.5.1 and Podman 5.8.6, and the dockerd half confirmed
// against dockerd 29.5.2.
func (d *imageNameChainDaemon) serveImport(w http.ResponseWriter, r *http.Request, normPath string) bool {
	if r.Method != http.MethodPost || (normPath != "/images/create" && normPath != "/libpod/images/import") {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if normPath == "/images/create" && d.param(r, "fromImage") != "" {
		return false
	}
	d.record(r, normPath)
	w.Header().Set("Content-Type", "application/json")

	id := d.newImage(nil)
	name := d.param(r, "reference")
	if normPath == "/images/create" {
		name = d.param(r, "repo")
		if name != "" {
			name = imageNameChainRepoTag(name, d.param(r, "tag"))
		}
	} else if name != "" {
		name = imageNameChainRepoTag(name, "")
	}
	if name != "" {
		d.names[d.landTagged(r, name)] = id
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": id})
	return true
}

func newImageImportChainDaemon() *imageNameChainDaemon {
	daemon := newImageNameChainDaemon()
	daemon.routes = append(daemon.routes, daemon.serveImport)
	return daemon
}

// imageImportChainStep is an import request: the query names the image and the
// body is the root filesystem.
func imageImportChainStep(target, reference, wantImage string, wantStatus int) imageNameChainStep {
	return imageNameChainStep{
		target:      target,
		body:        []byte("rootfs"),
		contentType: "application/x-tar",
		reference:   reference,
		wantImage:   wantImage,
		wantStatus:  wantStatus,
	}
}

// TestServeChainImportAuthorizesTheNameItAssigns sends image imports through
// the production handler chain to a daemon-shaped image store.
//
// An import makes an image from a tarball and names it in `repo` and `tag`.
// Nothing in owner isolation read that name, and the image an import makes
// carries no owner label, so a client could point a name another owner's
// image held at content of its own choosing, and with allow_unowned_images at
// its default the other owner would go on to run it. Every case asserts on
// the daemon's state: the name the request targets either still points where
// it did or was moved.
func TestServeChainImportAuthorizesTheNameItAssigns(t *testing.T) {
	denyUnowned := func(cfg *config.Config) { cfg.Ownership.AllowUnownedImages = false }

	tests := []struct {
		name      string
		configure func(*config.Config)
		step      imageNameChainStep
	}{
		{name: "foreign name by repo and tag", step: imageImportChainStep("/v1.45/images/create?fromSrc=-&repo=theirs%2Fapp&tag=latest", "theirs/app:latest", imageTagChainVictimID, http.StatusForbidden)},
		{name: "foreign name through the default tag", step: imageImportChainStep("/v1.45/images/create?fromSrc=-&repo=theirs%2Fapp", "theirs/app:latest", imageTagChainVictimID, http.StatusForbidden)},
		{name: "foreign name with the tag carried in repo", step: imageImportChainStep("/v1.45/images/create?fromSrc=-&repo=theirs%2Fapp%3Av1", "theirs/app:v1", imageTagChainVictimID, http.StatusForbidden)},
		{name: "foreign name with an empty fromImage", step: imageImportChainStep("/v1.45/images/create?fromImage=&fromSrc=-&repo=theirs%2Fapp&tag=v1", "theirs/app:v1", imageTagChainVictimID, http.StatusForbidden)},
		{name: "unlabeled holder is refused once unowned images are", configure: denyUnowned, step: imageImportChainStep("/v1.45/images/create?fromSrc=-&repo=shared%2Fbase", "shared/base:latest", imageTagChainUnownedID, http.StatusForbidden)},
		{name: "unlabeled holder follows allow_unowned_images", step: imageImportChainStep("/v1.45/images/create?fromSrc=-&repo=shared%2Fbase", "shared/base:latest", "", http.StatusOK)},
		{name: "new name is created", step: imageImportChainStep("/v1.45/images/create?fromSrc=-&repo=mine%2Fnew&tag=v2", "mine/new:v2", "", http.StatusOK)},
		{name: "caller moves its own name", step: imageImportChainStep("/v1.45/images/create?fromSrc=-&repo=mine&tag=stable", "mine:stable", "", http.StatusOK)},
		{name: "import that names nothing", step: imageImportChainStep("/v1.45/images/create?fromSrc=-", "", "", http.StatusOK)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := newImageImportChainDaemon()
			addr := newImageNameChain(t, daemon, tt.configure)
			tt.step.name = tt.name

			runImageNameChainStep(t, addr, daemon, tt.step)

			wantForwarded := tt.step.wantStatus == http.StatusOK
			if got := daemon.sawRequest(http.MethodPost, "/images/create"); got != wantForwarded {
				t.Errorf("import reached the daemon = %v, want %v; daemon saw %v", got, wantForwarded, daemon.requests)
			}
		})
	}
}

// TestServeChainImportChecksTheStoredNameOnPodman replays the import on a
// Podman-shaped store, where a name with no registry is stored under
// localhost/ on the native route, and on the compat one once
// compat_api_enforce_docker_hub is off.
func TestServeChainImportChecksTheStoredNameOnPodman(t *testing.T) {
	tests := []struct {
		name string
		step imageNameChainStep
	}{
		{name: "native import onto a short name", step: imageImportChainStep("/v5.0.0/libpod/images/import?reference=nginx%3Aprod", "localhost/nginx:prod", imageTagChainVictimID, http.StatusForbidden)},
		{name: "native import onto a short name through the default tag", step: imageImportChainStep("/v5.0.0/libpod/images/import?reference=theirs%2Fapp", "localhost/theirs/app:latest", imageTagChainVictimID, http.StatusForbidden)},
		{name: "compat import onto a short name", step: imageImportChainStep("/v1.41/images/create?fromSrc=-&repo=nginx&tag=prod", "localhost/nginx:prod", imageTagChainVictimID, http.StatusForbidden)},
		{name: "native import onto a name nothing holds", step: imageImportChainStep("/v5.0.0/libpod/images/import?reference=mine%2Fnew%3Av2", "localhost/mine/new:v2", "", http.StatusOK)},
		{name: "native import that names nothing", step: imageImportChainStep("/v5.0.0/libpod/images/import", "", "", http.StatusOK)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := newImageImportChainDaemon()
			daemon.names = map[string]string{
				"localhost/mine:1":             imageTagChainOwnID,
				"docker.io/library/nginx:prod": imageTagChainOwnID,
				"localhost/nginx:prod":         imageTagChainVictimID,
				"localhost/theirs/app:latest":  imageTagChainVictimID,
			}
			daemon.shortNameAliases = map[string]string{"nginx": "docker.io/library/nginx"}
			daemon.enforceDockerHubOff = true
			addr := newImageNameChain(t, daemon, nil)
			tt.step.name = tt.name

			runImageNameChainStep(t, addr, daemon, tt.step)
		})
	}
}
