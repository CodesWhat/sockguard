package cmd

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
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
	hasManifest := false
	repositories := map[string]map[string]string{}
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
			hasManifest = true
			_ = json.NewDecoder(archive).Decode(&manifest)
		case "config.json":
			_ = json.NewDecoder(archive).Decode(&labels)
		case "repositories":
			_ = json.NewDecoder(archive).Decode(&repositories)
		}
	}
	id := d.newImage(labels)
	// With no manifest.json, moby's classic store up to 28.x loads the archive
	// in its pre-1.10 layout and takes the names from `repositories`, whatever
	// else the archive holds (image/tarexport/load.go, legacyLoad). Podman
	// reads manifest.json or index.json and nothing else.
	if !hasManifest && d.legacyRepositories && !d.podman() {
		for name, tags := range repositories {
			for tag := range tags {
				d.names[name+":"+tag] = id
			}
		}
	}
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

// imageLoadChainOCIArchive is an OCI archive holding one image named name, with
// extra entries beside it.
func imageLoadChainOCIArchive(t *testing.T, name string, extra map[string][]byte) []byte {
	t.Helper()
	blobs := map[string][]byte{}
	blob := func(body []byte) string {
		digest := fmt.Sprintf("%x", sha256.Sum256(body))
		blobs["blobs/sha256/"+digest] = body
		return "sha256:" + digest
	}
	config := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"config":{}}`)
	manifest := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":%q,"size":%d},"layers":[]}`, blob(config), len(config)))
	index := []byte(fmt.Sprintf(`{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":%q,"size":%d,"annotations":{"io.containerd.image.name":%q}}]}`, blob(manifest), len(manifest), name))

	files := map[string][]byte{"oci-layout": []byte(`{"imageLayoutVersion":"1.0.0"}`), "index.json": index}
	for _, group := range []map[string][]byte{blobs, extra} {
		for path, body := range group {
			files[path] = body
		}
	}
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	slices.Sort(paths)

	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	for _, path := range paths {
		if err := writer.WriteHeader(&tar.Header{Name: path, Mode: 0o644, Size: int64(len(files[path])), Typeflag: tar.TypeReg}); err != nil {
			t.Fatalf("write %s header: %v", path, err)
		}
		if _, err := writer.Write(files[path]); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close archive: %v", err)
	}
	return archive.Bytes()
}

// TestServeChainLoadRefusesNamesInALegacyRepositoriesFile sends archives that
// carry the pre-1.10 `repositories` file through the production handler chain
// to a store that loads the way moby's classic one does up to 28.x: with no
// manifest.json in the archive it takes the image names from that file.
//
// The filter classes an archive by manifest.json and index.json, so one with
// an index.json and a `repositories` file read as an OCI archive whose only
// name was the index's. Owner isolation authorized that name, and the daemon
// assigned the ones in the file nobody had read. Every case asserts on the
// daemon's state.
func TestServeChainLoadRefusesNamesInALegacyRepositoriesFile(t *testing.T) {
	legacy := map[string][]byte{
		"repositories":    []byte(`{"theirs/app":{"latest":"blobs"}}`),
		"blobs/json":      []byte(`{"id":"blobs","os":"linux"}`),
		"blobs/layer.tar": []byte("layer"),
	}
	dockerAndLegacy := func(t *testing.T) []byte {
		t.Helper()
		var archive bytes.Buffer
		writer := tar.NewWriter(&archive)
		for _, file := range []struct {
			name string
			body []byte
		}{
			{"manifest.json", []byte(`[{"RepoTags":["mine/new:v2"]}]`)},
			{"config.json", []byte(`{}`)},
			{"repositories", legacy["repositories"]},
		} {
			if err := writer.WriteHeader(&tar.Header{Name: file.name, Mode: 0o644, Size: int64(len(file.body)), Typeflag: tar.TypeReg}); err != nil {
				t.Fatalf("write %s header: %v", file.name, err)
			}
			if _, err := writer.Write(file.body); err != nil {
				t.Fatalf("write %s: %v", file.name, err)
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("close archive: %v", err)
		}
		return archive.Bytes()
	}

	tests := []struct {
		name   string
		podman bool
		target string
		body   func(*testing.T) []byte
		// reference is the name the `repositories` file aims at.
		reference string
		// created is a name the load has to have made, when it goes through.
		created    string
		wantStatus int
	}{
		{
			name: "beside an OCI index", target: "/v1.45/images/load",
			body:      func(t *testing.T) []byte { return imageLoadChainOCIArchive(t, "mine/new:v2", legacy) },
			reference: "theirs/app:latest", wantStatus: http.StatusForbidden,
		},
		{
			// The daemon reads manifest.json and ignores the file, which is
			// what every `docker save` since 1.10 writes.
			name: "beside manifest.json", target: "/v1.45/images/load", body: dockerAndLegacy,
			reference: "theirs/app:latest", created: "mine/new:v2", wantStatus: http.StatusOK,
		},
		{
			// Podman reads no such file, and only Podman serves this route.
			name: "beside an OCI index on the native route", podman: true, target: "/v5.0.0/libpod/images/load",
			body:      func(t *testing.T) []byte { return imageLoadChainOCIArchive(t, "mine/new:v2", legacy) },
			reference: "localhost/theirs/app:latest", wantStatus: http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := newImageLoadChainDaemon()
			daemon.legacyRepositories = true
			if tt.podman {
				daemon.names = map[string]string{"localhost/theirs/app:latest": imageTagChainVictimID}
				daemon.shortNameAliases = map[string]string{}
			}
			addr := newImageNameChain(t, daemon, nil)

			runImageNameChainStep(t, addr, daemon, imageNameChainStep{
				name:        tt.name,
				target:      tt.target,
				body:        tt.body(t),
				contentType: "application/x-tar",
				reference:   tt.reference,
				wantImage:   imageTagChainVictimID,
				wantStatus:  tt.wantStatus,
			})
			if tt.created != "" && !strings.HasPrefix(daemon.nameTarget(tt.created), "sha256:new") {
				t.Errorf("%s points at %q, want the image the load made", tt.created, daemon.nameTarget(tt.created))
			}
		})
	}
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
