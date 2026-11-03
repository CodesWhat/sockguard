package filter

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/logging"
)

const ownerLabelTestKey = "com.sockguard.owner"

type ownerLabelTarEntry struct {
	name string
	body string
}

func ownerLabelTar(t *testing.T, entries ...ownerLabelTarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatalf("header %s: %v", e.name, err)
		}
		if _, err := tw.Write([]byte(e.body)); err != nil {
			t.Fatalf("write %s: %v", e.name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return buf.Bytes()
}

func ownerLabelConfig(labels map[string]string) string {
	var pairs []string
	for k, v := range labels {
		pairs = append(pairs, fmt.Sprintf("%q:%q", k, v))
	}
	return `{"architecture":"amd64","config":{"Labels":{` + strings.Join(pairs, ",") + `}}}`
}

func ownerLabelDigest(body string) (string, string) {
	sum := fmt.Sprintf("%x", sha256.Sum256([]byte(body)))
	return "sha256:" + sum, "blobs/sha256/" + sum
}

// ownerLabelDockerArchive is a Docker archive with one image per config body.
func ownerLabelDockerArchive(t *testing.T, configs ...string) []byte {
	t.Helper()
	var manifest []string
	var entries []ownerLabelTarEntry
	for i, config := range configs {
		name := fmt.Sprintf("%064d.json", i)
		manifest = append(manifest, fmt.Sprintf(`{"Config":%q,"RepoTags":["mine/app:v%d"],"Layers":[]}`, name, i))
		entries = append(entries, ownerLabelTarEntry{name, config})
	}
	entries = append(entries, ownerLabelTarEntry{"manifest.json", "[" + strings.Join(manifest, ",") + "]"})
	return ownerLabelTar(t, entries...)
}

// ownerLabelOCIArchive is an OCI archive of one image whose config is config.
func ownerLabelOCIArchive(t *testing.T, config string, dropConfig bool) []byte {
	t.Helper()
	configDigest, configPath := ownerLabelDigest(config)
	manifest := fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":%q,"size":%d},"layers":[]}`, configDigest, len(config))
	manifestDigest, manifestPath := ownerLabelDigest(manifest)
	index := fmt.Sprintf(`{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":%q,"size":%d,"annotations":{"org.opencontainers.image.ref.name":"mine/app:v1"}}]}`, manifestDigest, len(manifest))
	entries := []ownerLabelTarEntry{
		{"oci-layout", `{"imageLayoutVersion":"1.0.0"}`},
		{"index.json", index},
		{manifestPath, manifest},
	}
	if !dropConfig {
		entries = append(entries, ownerLabelTarEntry{configPath, config})
	}
	return ownerLabelTar(t, entries...)
}

func TestImageLoadRecordsOwnerLabels(t *testing.T) {
	foreign := ownerLabelConfig(map[string]string{ownerLabelTestKey: "victim"})
	own := ownerLabelConfig(map[string]string{ownerLabelTestKey: "mine"})
	none := ownerLabelConfig(map[string]string{"other": "x"})
	empty := ownerLabelConfig(map[string]string{ownerLabelTestKey: ""})

	tests := []struct {
		name           string
		path           string
		key            string
		body           []byte
		wantLabels     []string
		wantUnreadable bool
	}{
		{name: "docker foreign", path: "/images/load", key: ownerLabelTestKey, body: ownerLabelDockerArchive(t, foreign), wantLabels: []string{"victim"}},
		{name: "docker own and none", path: "/images/load", key: ownerLabelTestKey, body: ownerLabelDockerArchive(t, own, none), wantLabels: []string{"mine"}},
		{name: "docker label only in container_config", path: "/images/load", key: ownerLabelTestKey, body: ownerLabelDockerArchive(t, `{"container_config":{"Labels":{"`+ownerLabelTestKey+`":"victim"}}}`), wantLabels: []string{"victim"}},
		{name: "docker container_config ignored when config has labels", path: "/images/load", key: ownerLabelTestKey, body: ownerLabelDockerArchive(t, `{"config":{"Labels":{"a":"b"}},"container_config":{"Labels":{"`+ownerLabelTestKey+`":"victim"}}}`)},
		{name: "docker empty label adds nothing", path: "/images/load", key: ownerLabelTestKey, body: ownerLabelDockerArchive(t, empty)},
		{name: "docker second image foreign", path: "/images/load", key: ownerLabelTestKey, body: ownerLabelDockerArchive(t, own, foreign), wantLabels: []string{"mine", "victim"}},
		{name: "docker native route", path: "/v5.0.0/libpod/images/load", key: ownerLabelTestKey, body: ownerLabelDockerArchive(t, foreign), wantLabels: []string{"victim"}},
		{name: "docker config not json", path: "/images/load", key: ownerLabelTestKey, body: ownerLabelDockerArchive(t, "not json"), wantUnreadable: true},
		{name: "docker config missing", path: "/images/load", key: ownerLabelTestKey, body: ownerLabelTar(t, ownerLabelTarEntry{"manifest.json", `[{"Config":"gone.json","RepoTags":["mine/app:v1"]}]`}), wantUnreadable: true},
		{name: "docker entry names no config", path: "/images/load", key: ownerLabelTestKey, body: ownerLabelTar(t, ownerLabelTarEntry{"manifest.json", `[{"RepoTags":["mine/app:v1"]}]`}), wantUnreadable: true},
		{name: "oci foreign", path: "/images/load", key: ownerLabelTestKey, body: ownerLabelOCIArchive(t, foreign, false), wantLabels: []string{"victim"}},
		{name: "oci native route foreign", path: "/v5.0.0/libpod/images/load", key: ownerLabelTestKey, body: ownerLabelOCIArchive(t, foreign, false), wantLabels: []string{"victim"}},
		{name: "oci own", path: "/images/load", key: ownerLabelTestKey, body: ownerLabelOCIArchive(t, own, false), wantLabels: []string{"mine"}},
		{name: "oci none", path: "/images/load", key: ownerLabelTestKey, body: ownerLabelOCIArchive(t, none, false)},
		{name: "no key reads nothing", path: "/images/load", key: "", body: ownerLabelDockerArchive(t, foreign)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta := &logging.RequestMeta{}
			req := httptest.NewRequest(http.MethodPost, tt.path, bytes.NewReader(tt.body))
			req = req.WithContext(logging.WithMeta(req.Context(), meta))
			policy := newImageLoadPolicy(ImageLoadOptions{AllowAllRegistries: true, AllowUntagged: true, OwnerLabelKey: tt.key})
			reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
			if err != nil || reason != "" {
				// An OCI archive the structural checks refuse is not this test's concern.
				t.Fatalf("inspect() = %q, %v", reason, err)
			}
			got := meta.ImageLoad
			if got == nil {
				t.Fatal("no record")
			}
			slices.Sort(got.OwnerLabels)
			if !slices.Equal(got.OwnerLabels, tt.wantLabels) || got.ConfigsUnreadable != tt.wantUnreadable || got.OwnerLabelKey != tt.key {
				t.Fatalf("record = %+v, want labels %v unreadable %v key %q", got, tt.wantLabels, tt.wantUnreadable, tt.key)
			}
		})
	}
}

// A single-image OCI archive missing its config never reaches the label read:
// the structural check refuses it first.
func TestImageLoadOCIArchiveMissingConfigIsRefused(t *testing.T) {
	body := ownerLabelOCIArchive(t, ownerLabelConfig(nil), true)
	req := httptest.NewRequest(http.MethodPost, "/images/load", bytes.NewReader(body))
	policy := newImageLoadPolicy(ImageLoadOptions{AllowAllRegistries: true, AllowUntagged: true, OwnerLabelKey: ownerLabelTestKey})
	if reason, err := policy.inspect(nil, req, "/images/load"); err == nil && reason == "" {
		t.Fatal("want the archive refused")
	}
}

func TestImageLoadOwnerLabelsFailClosedPastBounds(t *testing.T) {
	t.Run("more configs than the bound", func(t *testing.T) {
		configs := make([]string, maxImageLoadConfigs+1)
		for i := range configs {
			configs[i] = fmt.Sprintf(`{"config":{"Labels":{"n":"%d"}}}`, i)
		}
		archive, err := (ioDeps{ReadAllLimited: defaultIODeps().ReadAllLimited}).extractImageLoadArchiveFromTar(tar.NewReader(bytes.NewReader(ownerLabelDockerArchive(t, configs...))), false)
		if err != nil {
			t.Fatal(err)
		}
		if _, unreadable := imageLoadOwnerLabels(archive, ownerLabelTestKey); !unreadable {
			t.Fatal("want unreadable past the config bound")
		}
	})
	t.Run("config past the per-file bound", func(t *testing.T) {
		big := `{"config":{"Labels":{"pad":"` + strings.Repeat("x", maxImageLoadManifestBytes) + `"}}}`
		archive, err := (ioDeps{ReadAllLimited: defaultIODeps().ReadAllLimited}).extractImageLoadArchiveFromTar(tar.NewReader(bytes.NewReader(ownerLabelDockerArchive(t, big))), false)
		if err != nil {
			t.Fatal(err)
		}
		if _, unreadable := imageLoadOwnerLabels(archive, ownerLabelTestKey); !unreadable {
			t.Fatal("want unreadable for an unretained config")
		}
	})
	t.Run("later copy of a config path replaces the earlier", func(t *testing.T) {
		name := fmt.Sprintf("%064d.json", 0)
		body := ownerLabelTar(t,
			ownerLabelTarEntry{name, ownerLabelConfig(map[string]string{ownerLabelTestKey: "mine"})},
			ownerLabelTarEntry{name, ownerLabelConfig(map[string]string{ownerLabelTestKey: "victim"})},
			ownerLabelTarEntry{"manifest.json", fmt.Sprintf(`[{"Config":%q,"RepoTags":["mine/app:v1"]}]`, name)},
		)
		archive, err := (ioDeps{ReadAllLimited: defaultIODeps().ReadAllLimited}).extractImageLoadArchiveFromTar(tar.NewReader(bytes.NewReader(body)), false)
		if err != nil {
			t.Fatal(err)
		}
		labels, unreadable := imageLoadOwnerLabels(archive, ownerLabelTestKey)
		if unreadable || !slices.Equal(labels, []string{"victim"}) {
			t.Fatalf("labels = %v unreadable = %v, want [victim]", labels, unreadable)
		}
	})
}
