package cmd

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/config"
)

// serveLoad is the image load of both engines: POST /images/load, and Podman's
// native POST /libpod/images/load. It reads the Docker archive in the body,
// makes one image carrying the labels the archive's config sets, and points
// every RepoTags entry of its manifest.json at that image, no matter what
// those names pointed at before.
//
// dockerd holds each name as the archive spells it. Podman completes it with
// libimage's NormalizeName on both routes, so a name with no registry is
// stored under localhost/ without a lookup. Read from moby 28.5.1 and from
// libimage (go.podman.io/common v0.67.1), and the dockerd half confirmed
// against dockerd 29.5.2.
func (d *imageNameChainDaemon) serveLoad(w http.ResponseWriter, r *http.Request, normPath string) bool {
	if r.Method != http.MethodPost || (normPath != "/images/load" && normPath != "/libpod/images/load") {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.record(r, normPath)
	w.Header().Set("Content-Type", "application/json")

	var manifest []struct {
		RepoTags []string `json:"RepoTags"`
	}
	labels := map[string]string{}
	archive := tar.NewReader(r.Body)
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return true
		}
		switch header.Name {
		case "manifest.json":
			_ = json.NewDecoder(archive).Decode(&manifest)
		case "config.json":
			_ = json.NewDecoder(archive).Decode(&labels)
		}
	}
	id := d.newImage(labels)
	for _, entry := range manifest {
		for _, name := range entry.RepoTags {
			if d.podman() && imageTagChainShortName(imageNameChainName(name)) {
				name = "localhost/" + name
			}
			d.names[name] = id
		}
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, `{"stream":"Loaded image"}`)
	return true
}

// imageLoadChainDigest is a well-formed digest for a name held by digest.
const imageLoadChainDigest = "sha256:5c02a4b1e0f3d2c6b7a8990f1e2d3c4b5a69788796a5b4c3d2e1f00112233445"

func newImageLoadChainDaemon() *imageNameChainDaemon {
	daemon := newImageNameChainDaemon()
	daemon.routes = append(daemon.routes, daemon.serveLoad)
	return daemon
}

// imageLoadChainArchive is a Docker archive naming repoTags, whose image
// carries labels.
func imageLoadChainArchive(t *testing.T, labels map[string]string, repoTags ...string) []byte {
	t.Helper()
	manifest, err := json.Marshal([]map[string][]string{{"RepoTags": repoTags}})
	if err != nil {
		t.Fatalf("encode manifest: %v", err)
	}
	config, err := json.Marshal(labels)
	if err != nil {
		t.Fatalf("encode config: %v", err)
	}
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	for name, body := range map[string][]byte{"manifest.json": manifest, "config.json": config} {
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatalf("write %s header: %v", name, err)
		}
		if _, err := writer.Write(body); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close archive: %v", err)
	}
	return archive.Bytes()
}

// TestServeChainLoadAuthorizesTheNamesItAssigns sends image loads through the
// production handler chain to a daemon-shaped image store.
//
// A load takes its image names from the archive, and its labels too. Owner
// isolation never looked inside one, so a client could load an archive that
// names another owner's image and carries that owner's label: the name moved
// to the client's content and still passed every ownership check its real
// owner made. Every case asserts on the daemon's state: the name the archive
// targets either still points where it did or was moved.
func TestServeChainLoadAuthorizesTheNamesItAssigns(t *testing.T) {
	denyUnowned := func(cfg *config.Config) { cfg.Ownership.AllowUnownedImages = false }
	forged := map[string]string{imageTagChainLabelKey: "team-b"}

	tests := []struct {
		name      string
		configure func(*config.Config)
		labels    map[string]string
		repoTags  []string
		target    string
		// podman makes the store Podman-shaped, with the victim's image under
		// the localhost/ name a load there writes.
		podman bool
		// held adds names to the store before the request.
		held       map[string]string
		reference  string
		wantImage  string
		wantStatus int
	}{
		{name: "foreign name under a forged owner label", labels: forged, repoTags: []string{"theirs/app:latest"}, target: "/v1.45/images/load", reference: "theirs/app:latest", wantImage: imageTagChainVictimID, wantStatus: http.StatusForbidden},
		{name: "foreign name behind one of the caller's own", repoTags: []string{"mine/new:v2", "theirs/app:v1"}, target: "/v1.45/images/load", reference: "theirs/app:v1", wantImage: imageTagChainVictimID, wantStatus: http.StatusForbidden},
		{name: "foreign name on a registry with a port", repoTags: []string{"registry.example:5000/theirs/app:v1"}, target: "/images/load", reference: "registry.example:5000/theirs/app:v1", wantImage: imageTagChainVictimID, wantStatus: http.StatusForbidden},
		{name: "unlabeled holder is refused once unowned images are", configure: denyUnowned, repoTags: []string{"shared/base:latest"}, target: "/v1.45/images/load", reference: "shared/base:latest", wantImage: imageTagChainUnownedID, wantStatus: http.StatusForbidden},
		{name: "unlabeled holder follows allow_unowned_images", repoTags: []string{"shared/base:latest"}, target: "/v1.45/images/load", reference: "shared/base:latest", wantStatus: http.StatusOK},
		{
			// A containerd-store dockerd writes a name by digest as an image
			// record of its own, whatever digest the loaded image has, so the
			// image that was held only under that reference loses it.
			// Confirmed against dockerd 29.5.2.
			name: "foreign name held only by digest", held: map[string]string{"theirs/pinned@" + imageLoadChainDigest: imageTagChainVictimID},
			repoTags: []string{"theirs/pinned@" + imageLoadChainDigest}, target: "/v1.45/images/load",
			reference: "theirs/pinned@" + imageLoadChainDigest, wantImage: imageTagChainVictimID, wantStatus: http.StatusForbidden,
		},
		{
			name: "foreign name by digest behind one of the caller's own", held: map[string]string{"theirs/pinned@" + imageLoadChainDigest: imageTagChainVictimID},
			repoTags: []string{"mine/new:v2", "theirs/pinned@" + imageLoadChainDigest}, target: "/v1.45/images/load",
			reference: "theirs/pinned@" + imageLoadChainDigest, wantImage: imageTagChainVictimID, wantStatus: http.StatusForbidden,
		},
		{name: "name by digest nothing holds", repoTags: []string{"mine/pinned@" + imageLoadChainDigest}, target: "/v1.45/images/load", reference: "mine/pinned@" + imageLoadChainDigest, wantStatus: http.StatusOK},
		{
			name: "caller reloads its own name by digest", held: map[string]string{"mine/pinned@" + imageLoadChainDigest: imageTagChainOwnID},
			repoTags: []string{"mine/pinned@" + imageLoadChainDigest}, target: "/v1.45/images/load", reference: "mine/pinned@" + imageLoadChainDigest, wantStatus: http.StatusOK,
		},
		{name: "new name is created", repoTags: []string{"mine/new:v2"}, target: "/v1.45/images/load", reference: "mine/new:v2", wantStatus: http.StatusOK},
		{name: "caller reloads its own name", repoTags: []string{"mine:stable"}, target: "/v1.45/images/load", reference: "mine:stable", wantStatus: http.StatusOK},
		{
			// The access logger carries the request metadata on the response
			// writer instead of on the context. The filter's record has to
			// reach ownership either way.
			name: "new name is created with access logging on", configure: func(cfg *config.Config) { cfg.Log.AccessLog = true },
			repoTags: []string{"mine/new:v2"}, target: "/v1.45/images/load", reference: "mine/new:v2", wantStatus: http.StatusOK,
		},
		{
			name: "foreign name with access logging on", configure: func(cfg *config.Config) { cfg.Log.AccessLog = true },
			repoTags: []string{"theirs/app:v1"}, target: "/v1.45/images/load", reference: "theirs/app:v1", wantImage: imageTagChainVictimID, wantStatus: http.StatusForbidden,
		},
		{name: "archive that names nothing", configure: func(cfg *config.Config) { cfg.RequestBody.ImageLoad.AllowUntagged = true }, target: "/v1.45/images/load", wantStatus: http.StatusOK},
		{name: "native load onto a short name", podman: true, labels: forged, repoTags: []string{"theirs/app:latest"}, target: "/v5.0.0/libpod/images/load", reference: "localhost/theirs/app:latest", wantImage: imageTagChainVictimID, wantStatus: http.StatusForbidden},
		{name: "compat load onto a short name on podman", podman: true, repoTags: []string{"theirs/app:latest"}, target: "/v1.41/images/load", reference: "localhost/theirs/app:latest", wantImage: imageTagChainVictimID, wantStatus: http.StatusForbidden},
		{name: "native load onto a name nothing holds", podman: true, repoTags: []string{"mine/new:v2"}, target: "/v5.0.0/libpod/images/load", reference: "localhost/mine/new:v2", wantStatus: http.StatusOK},
		{
			name: "native load onto a short name by digest", podman: true, held: map[string]string{"localhost/theirs/pinned@" + imageLoadChainDigest: imageTagChainVictimID},
			repoTags: []string{"theirs/pinned@" + imageLoadChainDigest}, target: "/v5.0.0/libpod/images/load",
			reference: "localhost/theirs/pinned@" + imageLoadChainDigest, wantImage: imageTagChainVictimID, wantStatus: http.StatusForbidden,
		},
		{
			name: "compat load onto a short name by digest on podman", podman: true, held: map[string]string{"localhost/theirs/pinned@" + imageLoadChainDigest: imageTagChainVictimID},
			repoTags: []string{"theirs/pinned@" + imageLoadChainDigest}, target: "/v1.41/images/load",
			reference: "localhost/theirs/pinned@" + imageLoadChainDigest, wantImage: imageTagChainVictimID, wantStatus: http.StatusForbidden,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := newImageLoadChainDaemon()
			if tt.podman {
				daemon.names = map[string]string{
					"localhost/mine:1":            imageTagChainOwnID,
					"localhost/theirs/app:latest": imageTagChainVictimID,
				}
				daemon.shortNameAliases = map[string]string{}
			}
			for name, id := range tt.held {
				daemon.names[name] = id
			}
			addr := newImageNameChain(t, daemon, tt.configure)

			runImageNameChainStep(t, addr, daemon, imageNameChainStep{
				name:        tt.name,
				target:      tt.target,
				body:        imageLoadChainArchive(t, tt.labels, tt.repoTags...),
				contentType: "application/x-tar",
				reference:   tt.reference,
				wantImage:   tt.wantImage,
				wantStatus:  tt.wantStatus,
			})
		})
	}
}
