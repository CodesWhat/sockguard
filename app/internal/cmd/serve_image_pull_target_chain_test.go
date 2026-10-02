package cmd

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/config"
)

const (
	imagePullChainRegistryID = "sha256:dddd"
	imagePullChainDigest     = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

// servePull is the image pull of both engines: POST /images/create with a
// `fromImage`, and Podman's native POST /libpod/images/pull. registry is what
// the registries serve, as stored name to image, and a pull points the local
// name at that image no matter what it pointed at before.
//
// dockerd builds the reference from `fromImage` and `tag`: a tag in
// `fromImage` is kept unless `tag` replaces it, a `tag` that parses as a
// digest makes it a pull by digest, and a name with neither pulls every tag
// the registry has for it. A pull by digest writes no tag.
//
// Podman joins the two the same way and pulls :latest for a bare name. A name
// some local image already holds is pulled under that image's name, alias
// first, unless the request names a platform, in which case the name goes
// through short-name resolution instead: the alias if there is one, Docker Hub
// otherwise in this store.
//
// Read from moby 28.5.1, Podman 5.8.6 and its libimage (go.podman.io/common
// v0.67.1, copySingleImageFromRegistry).
func (d *imageNameChainDaemon) servePull(registry map[string]string) func(http.ResponseWriter, *http.Request, string) bool {
	return func(w http.ResponseWriter, r *http.Request, normPath string) bool {
		if r.Method != http.MethodPost || (normPath != "/images/create" && normPath != "/libpod/images/pull") {
			return false
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		name, tag := d.param(r, "fromImage"), d.param(r, "tag")
		platform := d.param(r, "platform")
		if normPath == "/libpod/images/pull" {
			name, tag = strings.TrimPrefix(d.param(r, "reference"), "docker://"), ""
			platform = d.param(r, "Arch") + d.param(r, "OS") + d.param(r, "Variant")
		} else if name == "" {
			return false
		}
		d.record(r, normPath)
		w.Header().Set("Content-Type", "application/json")

		if strings.Contains(name, "@") || strings.Contains(tag, ":") {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"status":"pulled by digest"}`)
			return true
		}
		name = strings.TrimSuffix(name, ":")
		bare := imageNameChainName(name) == name && tag == ""
		if bare && !d.podman() {
			for stored, id := range registry {
				if imageNameChainName(stored) == name {
					d.names[stored] = id
				}
			}
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"status":"pulled every tag"}`)
			return true
		}
		ref := imageNameChainRepoTag(name, tag)
		stored := ref
		if d.podman() {
			stored = d.landPulled(ref, platform != "")
		}
		id, ok := registry[stored]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"message":"manifest unknown"}`)
			return true
		}
		d.names[stored] = id
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":"pulled"}`)
		return true
	}
}

// landPulled is the stored name Podman pulls ref under. The caller holds d.mu.
func (d *imageNameChainDaemon) landPulled(ref string, customPlatform bool) string {
	if held, ok := d.resolve(ref); ok && !customPlatform {
		return held
	}
	name := imageNameChainName(ref)
	if !imageTagChainShortName(name) {
		return ref
	}
	if alias, ok := d.shortNameAliases[name]; ok {
		return alias + strings.TrimPrefix(ref, name)
	}
	return imageTagChainDockerHubName(ref)
}

func newImagePullChainDaemon(registry map[string]string) *imageNameChainDaemon {
	daemon := newImageNameChainDaemon()
	daemon.labels[imagePullChainRegistryID] = nil
	daemon.routes = append(daemon.routes, daemon.servePull(registry))
	return daemon
}

func imagePullChainStep(target, reference, wantImage string, wantStatus int) imageNameChainStep {
	return imageNameChainStep{target: target, reference: reference, wantImage: wantImage, wantStatus: wantStatus}
}

// TestServeChainPullAuthorizesTheNameItOverwrites sends image pulls through
// the production handler chain to a daemon-shaped image store.
//
// A pull writes a local name: whatever the registry serves under it replaces
// whatever image held it. Owner isolation never looked at a pull, so a client
// could point a name another owner had built or tagged locally at the
// registry's content, which is not stamped and which any owner may run while
// allow_unowned_images is at its default. Every case asserts on the daemon's
// state: the name the request targets either still points where it did or was
// moved.
func TestServeChainPullAuthorizesTheNameItOverwrites(t *testing.T) {
	denyUnowned := func(cfg *config.Config) { cfg.Ownership.AllowUnownedImages = false }
	registry := map[string]string{
		"theirs/app:latest":  imagePullChainRegistryID,
		"theirs/app:v1":      imagePullChainRegistryID,
		"shared/base:latest": imagePullChainRegistryID,
		"mine:stable":        imagePullChainRegistryID,
		"fresh/app:1":        imagePullChainRegistryID,
	}

	tests := []struct {
		name      string
		configure func(*config.Config)
		step      imageNameChainStep
	}{
		{name: "foreign name by fromImage and tag", step: imagePullChainStep("/v1.45/images/create?fromImage=theirs%2Fapp&tag=latest", "theirs/app:latest", imageTagChainVictimID, http.StatusForbidden)},
		{name: "foreign name with the tag carried in fromImage", step: imagePullChainStep("/v1.45/images/create?fromImage=theirs%2Fapp%3Av1", "theirs/app:v1", imageTagChainVictimID, http.StatusForbidden)},
		{name: "foreign name behind a tag the tag parameter replaces", step: imagePullChainStep("/v1.45/images/create?fromImage=theirs%2Fapp%3Anone&tag=v1", "theirs/app:v1", imageTagChainVictimID, http.StatusForbidden)},
		{name: "every tag of a repository", step: imagePullChainStep("/v1.45/images/create?fromImage=theirs%2Fapp", "theirs/app:v1", imageTagChainVictimID, http.StatusForbidden)},
		{name: "every tag of a repository through a trailing colon", step: imagePullChainStep("/v1.45/images/create?fromImage=theirs%2Fapp%3A", "theirs/app:latest", imageTagChainVictimID, http.StatusForbidden)},
		{name: "unlabeled holder is refused once unowned images are", configure: denyUnowned, step: imagePullChainStep("/v1.45/images/create?fromImage=shared%2Fbase&tag=latest", "shared/base:latest", imageTagChainUnownedID, http.StatusForbidden)},
		{name: "unlabeled holder follows allow_unowned_images", step: imagePullChainStep("/v1.45/images/create?fromImage=shared%2Fbase&tag=latest", "shared/base:latest", imagePullChainRegistryID, http.StatusOK)},
		{name: "name nothing holds", step: imagePullChainStep("/v1.45/images/create?fromImage=fresh%2Fapp&tag=1", "fresh/app:1", imagePullChainRegistryID, http.StatusOK)},
		{name: "caller refreshes its own name", step: imagePullChainStep("/v1.45/images/create?fromImage=mine&tag=stable", "mine:stable", imagePullChainRegistryID, http.StatusOK)},
		{name: "pull by digest in the tag parameter writes no tag", step: imagePullChainStep("/v1.45/images/create?fromImage=theirs%2Fapp&tag="+imagePullChainDigest, "theirs/app:latest", imageTagChainVictimID, http.StatusOK)},
		{name: "pull by digest in fromImage writes no tag", step: imagePullChainStep("/v1.45/images/create?fromImage=theirs%2Fapp%40"+imagePullChainDigest, "theirs/app:latest", imageTagChainVictimID, http.StatusOK)},
		{name: "pull by tag and digest in fromImage writes no tag", step: imagePullChainStep("/v1.45/images/create?fromImage=theirs%2Fapp%3Av1%40"+imagePullChainDigest, "theirs/app:v1", imageTagChainVictimID, http.StatusOK)},
		{name: "pull by a tag in fromImage and a digest in tag writes no tag", step: imagePullChainStep("/v1.45/images/create?fromImage=theirs%2Fapp%3Av1&tag="+imagePullChainDigest, "theirs/app:v1", imageTagChainVictimID, http.StatusOK)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := newImagePullChainDaemon(registry)
			addr := newImageNameChain(t, daemon, tt.configure)
			tt.step.name = tt.name

			runImageNameChainStep(t, addr, daemon, tt.step)

			wantForwarded := tt.step.wantStatus == http.StatusOK
			if got := daemon.sawRequest(http.MethodPost, "/images/create"); got != wantForwarded {
				t.Errorf("pull reached the daemon = %v, want %v; daemon saw %v", got, wantForwarded, daemon.requests)
			}
		})
	}
}

// TestServeChainPullChecksTheNameItResolvesToOnPodman replays the pull on a
// Podman-shaped store.
//
// Podman pulls a name a local image already holds under that image's name,
// and the inspect of the name as spelled resolves the same way, so it answers
// for the image the pull replaces. A pull that names a platform skips that
// lookup and resolves a short name through registries.conf, which this layer
// cannot read, so it is refused unless the name spells its registry.
func TestServeChainPullChecksTheNameItResolvesToOnPodman(t *testing.T) {
	registry := map[string]string{
		"docker.io/library/nginx:prod": imagePullChainRegistryID,
		"docker.io/library/tool:1":     imagePullChainRegistryID,
		"docker.io/fresh/app:1":        imagePullChainRegistryID,
		"quay.io/team/tool:1":          imagePullChainRegistryID,
	}

	tests := []struct {
		name string
		step imageNameChainStep
	}{
		{name: "compat pull of a short name an alias resolves to another owner's image", step: imagePullChainStep("/v1.41/images/create?fromImage=nginx&tag=prod", "docker.io/library/nginx:prod", imageTagChainVictimID, http.StatusForbidden)},
		{name: "native pull of a short name an alias resolves to another owner's image", step: imagePullChainStep("/v5.0.0/libpod/images/pull?reference=nginx%3Aprod", "docker.io/library/nginx:prod", imageTagChainVictimID, http.StatusForbidden)},
		{name: "native pull spelled with the docker transport", step: imagePullChainStep("/v5.0.0/libpod/images/pull?reference=docker%3A%2F%2Fdocker.io%2Flibrary%2Fnginx%3Aprod", "docker.io/library/nginx:prod", imageTagChainVictimID, http.StatusForbidden)},
		{name: "native pull of every tag", step: imagePullChainStep("/v5.0.0/libpod/images/pull?reference=docker.io%2Flibrary%2Fnginx&allTags=true", "docker.io/library/nginx:prod", imageTagChainVictimID, http.StatusForbidden)},
		{
			// The caller's own image holds the localhost/ name the lookup
			// finds. Naming a platform makes Podman skip that lookup and pull
			// the Docker Hub name, which another owner's image holds.
			name: "native pull of a short name for a named platform",
			step: imagePullChainStep("/v5.0.0/libpod/images/pull?reference=tool%3A1&Arch=arm64", "docker.io/library/tool:1", imageTagChainVictimID, http.StatusForbidden),
		},
		{name: "compat pull of a short name for a named platform", step: imagePullChainStep("/v1.41/images/create?fromImage=tool&tag=1&platform=linux%2Farm64", "docker.io/library/tool:1", imageTagChainVictimID, http.StatusForbidden)},
		{name: "native pull for a named platform with the registry spelled", step: imagePullChainStep("/v5.0.0/libpod/images/pull?reference=quay.io%2Fteam%2Ftool%3A1&Arch=arm64", "quay.io/team/tool:1", imagePullChainRegistryID, http.StatusOK)},
		{name: "native pull of a name nothing holds", step: imagePullChainStep("/v5.0.0/libpod/images/pull?reference=fresh%2Fapp%3A1", "docker.io/fresh/app:1", imagePullChainRegistryID, http.StatusOK)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := newImagePullChainDaemon(registry)
			daemon.names = map[string]string{
				"localhost/mine:1":             imageTagChainOwnID,
				"localhost/tool:1":             imageTagChainOwnID,
				"docker.io/library/tool:1":     imageTagChainVictimID,
				"docker.io/library/nginx:prod": imageTagChainVictimID,
			}
			daemon.shortNameAliases = map[string]string{"nginx": "docker.io/library/nginx"}
			daemon.enforceDockerHubOff = true
			addr := newImageNameChain(t, daemon, nil)
			tt.step.name = tt.name

			runImageNameChainStep(t, addr, daemon, tt.step)
		})
	}
}
