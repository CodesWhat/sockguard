package filter_test

import (
	"net/http"
	"strings"
	"testing"
)

func TestDiunPresetDocumentationIncludesIncidentalImageList(t *testing.T) {
	section := presetDocsSection(t, "## Diun (`diun.yaml`)", "## Autoheal (`autoheal.yaml`)")
	if !strings.Contains(section, "`GET /images/json`") {
		t.Fatal("Diun preset documentation must disclose the incidentally allowed image-list route GET /images/json")
	}
}

// TestDiunPresetConformance proves the shipped diun.yaml admits every
// endpoint Diun's Docker provider actually calls while denying the
// read-exfiltration surface the old "/containers/**" and "/images/**" globs
// let through.
//
// The allow set is taken from crazy-max/diun master. Its whole Docker socket
// surface is three calls: pkg/docker/client.go:60 does ServerVersion as a
// connection check, and internal/provider/docker/container.go calls
// ContainerList (line 37) and ImageInspect (line 46). IsLocalImage,
// IsDanglingImage and IsDigest are pure functions over the already-fetched
// inspect result. Diun pins github.com/moby/moby/client v0.4.1, whose
// ImageInspect maps to GET /images/{name}/json (client/image_inspect.go:44).
//
// It reuses presetCase/buildDrydockPresetHandler/fireDrydockCase from
// drydock_preset_conformance_test.go and exfilDenialCases/
// assertPresetDoesNotAckReadExfiltration from
// traefik_homepage_preset_conformance_test.go — same package, same
// conventions.
func TestDiunPresetConformance(t *testing.T) {
	assertPresetDoesNotAckReadExfiltration(t, "diun.yaml")
	handler := buildDrydockPresetHandler(t, "diun.yaml")

	cases := []presetCase{
		// Health + metadata.
		{"ping-get", http.MethodGet, "/_ping", "", true},
		{"ping-head", http.MethodHead, "/_ping", "", true},
		{"version", http.MethodGet, "/version", "", true},

		// Container discovery.
		{"containers-list", http.MethodGet, "/containers/json", "", true},

		// Image inspect. Docker registers GET /images/{name:.*}/json and
		// {name:.*} spans slashes, so a registry-qualified image name is a
		// multi-segment path. These three are the shapes Diun really sends:
		// a bare library name, a fully-qualified name, and a digest.
		{"image-inspect-bare", http.MethodGet, "/images/nginx/json", "", true},
		{"image-inspect-tagged", http.MethodGet, "/images/nginx:1.27/json", "", true},
		{"image-inspect-fully-qualified", http.MethodGet, "/images/docker.io/library/nginx/json", "", true},
		{"image-inspect-registry-qualified", http.MethodGet, "/images/ghcr.io/crazy-max/diun:latest/json", "", true},
		{"image-inspect-digest", http.MethodGet, "/images/sha256:0000000000000000000000000000000000000000000000000000000000000000/json", "", true},

		// "/images/**/json" also admits the image list, because "/**" can
		// match nothing. Pinned so the widening is visible rather than
		// discovered later — it is a metadata read, not an exfiltration
		// endpoint.
		{"images-list-incidentally-allowed", http.MethodGet, "/images/json", "", true},

		// Version-prefixed forms of the same reads.
		{"v-prefixed-containers-list", http.MethodGet, "/v1.45/containers/json", "", true},
		{"v-prefixed-image-inspect-fully-qualified", http.MethodGet, "/v1.45/images/docker.io/library/nginx/json", "", true},

		// Reads Diun never makes stay denied — the narrowing is a rule list,
		// not a "GET is fine" posture. Container inspect in particular:
		// pkg/docker/image.go defines ContainerInspect but the Docker
		// provider never calls it.
		{"container-inspect-denied", http.MethodGet, "/containers/abc/json", "", false},
		{"container-stats-denied", http.MethodGet, "/containers/abc/stats", "", false},
		{"info-denied", http.MethodGet, "/info", "", false},
		{"events-denied", http.MethodGet, "/events", "", false},
		{"networks-list-denied", http.MethodGet, "/networks", "", false},
		{"services-list-denied", http.MethodGet, "/services", "", false},

		// The /json anchor is what keeps "**" narrow. Every other route
		// under /images/{name:.*} must stay denied, including the
		// multi-segment forms that only "**" could ever have reached.
		{"image-history-denied", http.MethodGet, "/images/nginx/history", "", false},
		{"image-attestations-denied", http.MethodGet, "/images/nginx/attestations", "", false},
		{"image-get-fully-qualified-denied", http.MethodGet, "/images/docker.io/library/nginx/get", "", false},
		{"image-push-fully-qualified-denied", http.MethodPost, "/images/docker.io/library/nginx/push", "", false},

		// Writes stay denied.
		{"container-create-denied", http.MethodPost, "/containers/create", "", false},
		{"container-start-denied", http.MethodPost, "/containers/abc/start", "", false},
		{"container-delete-denied", http.MethodDelete, "/containers/abc", "", false},
		{"image-pull-denied", http.MethodPost, "/images/create", "", false},
		{"image-delete-denied", http.MethodDelete, "/images/nginx", "", false},
		{"exec-create-denied", http.MethodPost, "/containers/abc/exec", "", false},
	}
	cases = append(cases, exfilDenialCases...)

	for _, c := range cases {
		fireDrydockCase(t, handler, c)
	}
}
