package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/config"
)

// serveCommit is the commit endpoint of both engines: POST /commit, and
// Podman's native POST /libpod/commit. It makes an image from the body's
// config and, when the request names one, points `repo`:`tag` at it no matter
// what that name pointed at before.
func (d *imageNameChainDaemon) serveCommit(w http.ResponseWriter, r *http.Request, normPath string) bool {
	if r.Method != http.MethodPost || (normPath != "/commit" && normPath != "/libpod/commit") {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.record(r, normPath)
	w.Header().Set("Content-Type", "application/json")

	if _, ok := d.containers[d.param(r, "container")]; !ok {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"message":"No such container"}`)
		return true
	}
	var config struct {
		Labels map[string]string `json:"Labels"`
	}
	_ = json.NewDecoder(r.Body).Decode(&config)
	id := d.newImage(config.Labels)
	if repo := d.param(r, "repo"); repo != "" {
		d.names[d.landResolved(r, imageNameChainRepoTag(repo, d.param(r, "tag")))] = id
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"Id": id})
	return true
}

func newImageCommitChainDaemon() *imageNameChainDaemon {
	daemon := newImageNameChainDaemon()
	daemon.routes = append(daemon.routes, daemon.serveCommit)
	return daemon
}

// TestServeChainCommitAuthorizesTheNameItAssigns sends commits through the
// production handler chain to a daemon-shaped image store.
//
// A commit names a container and, optionally, a reference for the image it
// makes. Owner isolation checked the container and stamped the new image, and
// let the reference through unread, so a client could commit one of its own
// containers onto a name another owner's image held. The image it made carried
// the client's label, so the other owner lost the name and every later request
// that used it. Every case asserts on the daemon's state: the name the request
// targets either still points where it did or was moved.
func TestServeChainCommitAuthorizesTheNameItAssigns(t *testing.T) {
	denyUnowned := func(cfg *config.Config) { cfg.Ownership.AllowUnownedImages = false }

	tests := []struct {
		name      string
		configure func(*config.Config)
		step      imageNameChainStep
	}{
		{
			name: "foreign name by repo and tag",
			step: imageNameChainStep{
				target:    "/v1.45/commit?container=" + imageNameChainOwnContainer + "&repo=theirs%2Fapp&tag=latest",
				reference: "theirs/app:latest", wantImage: imageTagChainVictimID, wantStatus: http.StatusForbidden,
			},
		},
		{
			name: "foreign name through the default tag",
			step: imageNameChainStep{
				target:    "/v1.45/commit?container=" + imageNameChainOwnContainer + "&repo=theirs%2Fapp",
				reference: "theirs/app:latest", wantImage: imageTagChainVictimID, wantStatus: http.StatusForbidden,
			},
		},
		{
			name: "foreign name with the tag carried in repo",
			step: imageNameChainStep{
				target:    "/v1.45/commit?container=" + imageNameChainOwnContainer + "&repo=theirs%2Fapp%3Av1",
				reference: "theirs/app:v1", wantImage: imageTagChainVictimID, wantStatus: http.StatusForbidden,
			},
		},
		{
			name: "foreign name on the unversioned path",
			step: imageNameChainStep{
				target:    "/commit?container=" + imageNameChainOwnContainer + "&repo=theirs%2Fapp&tag=v1",
				reference: "theirs/app:v1", wantImage: imageTagChainVictimID, wantStatus: http.StatusForbidden,
			},
		},
		{
			name:      "unlabeled holder is refused once unowned images are",
			configure: denyUnowned,
			step: imageNameChainStep{
				target:    "/v1.45/commit?container=" + imageNameChainOwnContainer + "&repo=shared%2Fbase",
				reference: "shared/base:latest", wantImage: imageTagChainUnownedID, wantStatus: http.StatusForbidden,
			},
		},
		{
			name: "unlabeled holder follows allow_unowned_images",
			step: imageNameChainStep{
				target:    "/v1.45/commit?container=" + imageNameChainOwnContainer + "&repo=shared%2Fbase",
				reference: "shared/base:latest", wantStatus: http.StatusCreated,
			},
		},
		{
			name: "new name is created",
			step: imageNameChainStep{
				target:    "/v1.45/commit?container=" + imageNameChainOwnContainer + "&repo=mine%2Fsnap&tag=v2",
				reference: "mine/snap:v2", wantStatus: http.StatusCreated,
			},
		},
		{
			name: "caller moves its own name",
			step: imageNameChainStep{
				target:    "/v1.45/commit?container=" + imageNameChainOwnContainer + "&repo=mine&tag=stable",
				reference: "mine:stable", wantStatus: http.StatusCreated,
			},
		},
		{
			name: "commit that names nothing",
			step: imageNameChainStep{
				target:     "/v1.45/commit?container=" + imageNameChainOwnContainer,
				wantStatus: http.StatusCreated,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := newImageCommitChainDaemon()
			addr := newImageNameChain(t, daemon, tt.configure)
			tt.step.name = tt.name

			runImageNameChainStep(t, addr, daemon, tt.step)

			wantForwarded := tt.step.wantStatus == http.StatusCreated
			if got := daemon.sawRequest(http.MethodPost, "/commit"); got != wantForwarded {
				t.Errorf("commit reached the daemon = %v, want %v; daemon saw %v", got, wantForwarded, daemon.requests)
			}
		})
	}
}

// TestServeChainCommitChecksTheNameItResolvesToOnPodman replays the commit on
// a Podman-shaped store, on both of its routes.
//
// Podman resolves the name of a commit against local images before it writes
// it, alias first. The inspect of the name as spelled resolves the same way,
// so it answers for the image whose name the commit would move. The native
// route has no other reading, so it is checked under the name as spelled as
// well as under localhost/, which is all a retag on that route needs.
func TestServeChainCommitChecksTheNameItResolvesToOnPodman(t *testing.T) {
	tests := []struct {
		name string
		step imageNameChainStep
		// wantInspects is every image inspect the daemon answered.
		wantInspects []string
	}{
		{
			name: "compat commit onto a short name an alias resolves to another owner's image",
			step: imageNameChainStep{
				target:    "/v1.41/commit?container=" + imageNameChainOwnContainer + "&repo=nginx&tag=prod",
				reference: "docker.io/library/nginx:prod", wantImage: imageTagChainVictimID, wantStatus: http.StatusForbidden,
			},
			wantInspects: []string{"nginx:prod"},
		},
		{
			name: "native commit onto a short name an alias resolves to another owner's image",
			step: imageNameChainStep{
				target:    "/v5.0.0/libpod/commit?container=" + imageNameChainOwnContainer + "&repo=nginx&tag=prod",
				reference: "docker.io/library/nginx:prod", wantImage: imageTagChainVictimID, wantStatus: http.StatusForbidden,
			},
			wantInspects: []string{"nginx:prod"},
		},
		{
			name: "native commit onto a name nothing holds lands under localhost",
			step: imageNameChainStep{
				target:    "/v5.0.0/libpod/commit?container=" + imageNameChainOwnContainer + "&repo=mine%2Fsnap&tag=v2",
				reference: "localhost/mine/snap:v2", wantStatus: http.StatusCreated,
			},
			wantInspects: []string{"mine/snap:v2", "localhost/mine/snap:v2"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := newImageCommitChainDaemon()
			daemon.names = map[string]string{
				"localhost/mine:1":             imageTagChainOwnID,
				"docker.io/library/nginx:prod": imageTagChainVictimID,
			}
			daemon.shortNameAliases = map[string]string{"nginx": "docker.io/library/nginx"}
			addr := newImageNameChain(t, daemon, nil)
			tt.step.name = tt.name

			runImageNameChainStep(t, addr, daemon, tt.step)

			if got := daemon.inspects(); !slices.Equal(got, tt.wantInspects) {
				t.Errorf("inspects the daemon answered = %v, want %v", got, tt.wantInspects)
			}
		})
	}
}
