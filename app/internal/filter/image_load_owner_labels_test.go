package filter

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"errors"
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

// A non-regular entry at a config path replaces what an earlier regular entry
// put there, and carries no body to read, so the lookup has to refuse.
func TestImageLoadNonRegularEntryAtConfigPathFailsClosed(t *testing.T) {
	name := fmt.Sprintf("%064d.json", 0)
	manifest := fmt.Sprintf(`[{"Config":%q,"RepoTags":["mine/app:v1"]}]`, name)
	for _, typeflag := range []byte{tar.TypeSymlink, tar.TypeLink, tar.TypeChar, tar.TypeFifo, tar.TypeDir} {
		t.Run(fmt.Sprintf("typeflag %q after a regular entry", typeflag), func(t *testing.T) {
			var buf bytes.Buffer
			tw := tar.NewWriter(&buf)
			config := ownerLabelConfig(map[string]string{ownerLabelTestKey: "mine"})
			if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(config)), Typeflag: tar.TypeReg}); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write([]byte(config)); err != nil {
				t.Fatal(err)
			}
			hdr := &tar.Header{Name: name, Mode: 0o644, Typeflag: typeflag}
			if typeflag == tar.TypeSymlink || typeflag == tar.TypeLink {
				hdr.Linkname = "elsewhere.json"
			}
			if err := tw.WriteHeader(hdr); err != nil {
				t.Fatal(err)
			}
			if err := tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0o644, Size: int64(len(manifest)), Typeflag: tar.TypeReg}); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write([]byte(manifest)); err != nil {
				t.Fatal(err)
			}
			if err := tw.Close(); err != nil {
				t.Fatal(err)
			}
			archive, err := (ioDeps{ReadAllLimited: defaultIODeps().ReadAllLimited}).extractImageLoadArchiveFromTar(tar.NewReader(&buf), false)
			if errors.Is(err, errImageLoadOCIUninspectable) {
				return // links refuse the whole archive as uninspectable
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, unreadable := imageLoadOwnerLabels(archive, ownerLabelTestKey); !unreadable {
				t.Fatal("want unreadable after a non-regular entry at a retained config path")
			}
		})
	}
	t.Run("symlink at a path never retained", func(t *testing.T) {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Typeflag: tar.TypeSymlink, Linkname: "elsewhere.json"}); err != nil {
			t.Fatal(err)
		}
		if err := tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0o644, Size: int64(len(manifest)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(manifest)); err != nil {
			t.Fatal(err)
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		archive, err := (ioDeps{ReadAllLimited: defaultIODeps().ReadAllLimited}).extractImageLoadArchiveFromTar(tar.NewReader(&buf), false)
		if errors.Is(err, errImageLoadOCIUninspectable) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, unreadable := imageLoadOwnerLabels(archive, ownerLabelTestKey); !unreadable {
			t.Fatal("want unreadable")
		}
	})
}

func TestImageLoadOwnerLabelRetentionBudgets(t *testing.T) {
	t.Parallel()
	configAtSize := func(size int, owner string) string {
		body := ownerLabelConfig(map[string]string{ownerLabelTestKey: owner})
		return body + strings.Repeat(" ", size-len(body))
	}
	check := func(t *testing.T, entries []containerArchiveTestEntry, selected []string, wantUnreadable bool) {
		t.Helper()
		var manifests []string
		for _, name := range selected {
			manifests = append(manifests, fmt.Sprintf(`{"Config":%q,"RepoTags":["mine/app:v1"]}`, name))
		}
		entries = append(entries, containerArchiveTestEntry{name: "manifest.json", body: "[" + strings.Join(manifests, ",") + "]"})
		body := mustContainerArchiveTar(t, entries...)
		archive, err := defaultIODeps().extractImageLoadArchiveFromTar(tar.NewReader(bytes.NewReader(body)), false)
		if err != nil {
			t.Fatal(err)
		}
		labels, unreadable := imageLoadOwnerLabels(archive, ownerLabelTestKey)
		if unreadable != wantUnreadable {
			t.Fatalf("owner labels=%v unreadable=%v, want unreadable=%v", labels, unreadable, wantUnreadable)
		}
		if !wantUnreadable {
			want := make([]string, len(selected))
			for i := range want {
				want[i] = "mine"
			}
			if !slices.Equal(labels, want) {
				t.Fatalf("owner labels=%v, want %v", labels, want)
			}
		}
	}
	for _, mode := range []string{"regular", "discarded"} {
		for _, delta := range []int{-1, 0, 1} {
			t.Run(fmt.Sprintf("%s config count limit%+d", mode, delta), func(t *testing.T) {
				entries := []containerArchiveTestEntry{{name: "target.json", body: ownerLabelConfig(map[string]string{ownerLabelTestKey: "mine"})}}
				for i := 1; i < maxImageLoadConfigFiles+delta; i++ {
					entry := containerArchiveTestEntry{name: fmt.Sprintf("extra%04d.json", i), body: `{}`}
					if mode == "discarded" {
						entry.typ, entry.body = tar.TypeDir, ""
					}
					entries = append(entries, entry)
				}
				check(t, entries, []string{"target.json"}, delta > 0)
			})
		}
	}
	for _, delta := range []int{-1, 0, 1} {
		t.Run(fmt.Sprintf("per-file bytes limit%+d", delta), func(t *testing.T) {
			check(t, []containerArchiveTestEntry{{name: "target.json", body: configAtSize(maxImageLoadManifestBytes+delta, "mine")}}, []string{"target.json"}, delta > 0)
		})
		t.Run(fmt.Sprintf("aggregate bytes limit%+d", delta), func(t *testing.T) {
			var entries []containerArchiveTestEntry
			for i := range 15 {
				entries = append(entries, containerArchiveTestEntry{name: fmt.Sprintf("extra%02d.json", i), body: configAtSize(maxImageLoadManifestBytes, "mine")})
			}
			entries = append(entries, containerArchiveTestEntry{name: "padding.json", body: configAtSize(maxImageLoadManifestBytes-256, "mine")}, containerArchiveTestEntry{name: "target.json", body: configAtSize(256+delta, "mine")})
			check(t, entries, []string{"target.json"}, delta > 0)
		})
	}
	t.Run("replacement releases previous bytes", func(t *testing.T) {
		var entries []containerArchiveTestEntry
		for i := range 15 {
			entries = append(entries, containerArchiveTestEntry{name: fmt.Sprintf("extra%02d.json", i), body: configAtSize(maxImageLoadManifestBytes, "mine")})
		}
		entries = append(entries,
			containerArchiveTestEntry{name: "padding.json", body: configAtSize(maxImageLoadManifestBytes-512, "mine")},
			containerArchiveTestEntry{name: "target.json", body: configAtSize(256, "victim")},
			containerArchiveTestEntry{name: "target.json", body: configAtSize(256, "mine")},
			containerArchiveTestEntry{name: "after.json", body: configAtSize(256, "mine")},
		)
		check(t, entries, []string{"target.json", "after.json"}, false)
	})
}

func TestImageLoadOCIGraphBoundaries(t *testing.T) {
	t.Parallel()
	const manifestType = "application/vnd.oci.image.manifest.v1+json"
	const indexType = "application/vnd.oci.image.index.v1+json"
	for _, tt := range []struct {
		name           string
		depth, members int
		wantErr        string
	}{
		{name: "below depth limit", depth: 15, members: 1},
		{name: "exact depth limit", depth: 16, members: 1},
		{name: "above depth limit", depth: 17, members: 1, wantErr: "16 levels"},
		{name: "below visit limit", depth: 1, members: maxImageLoadOCIDescriptorVisits - 2},
		{name: "exact visit limit", depth: 1, members: maxImageLoadOCIDescriptorVisits - 1},
		{name: "above visit limit", depth: 1, members: maxImageLoadOCIDescriptorVisits, wantErr: "descriptor visit limit"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			controls := imageLoadArchiveControlFiles{seenOCIIndex: true}
			entries := []containerArchiveTestEntry{{name: "oci-layout", body: `{"imageLayoutVersion":"1.0.0"}`}}
			add := func(body string, mediaType string) imageLoadOCIIndexDescriptor {
				t.Helper()
				digest, name := ownerLabelDigest(body)
				entries = append(entries, containerArchiveTestEntry{name: name, body: body})
				if err := defaultIODeps().recordImageLoadOCIBlob(&controls, name, &tar.Header{Typeflag: tar.TypeReg, Size: int64(len(body))}, strings.NewReader(body)); err != nil {
					t.Fatal(err)
				}
				return imageLoadOCIIndexDescriptor{Digest: digest, Size: int64(len(body)), MediaType: mediaType}
			}
			config := add(ownerLabelConfig(map[string]string{ownerLabelTestKey: "mine"}), "application/vnd.oci.image.config.v1+json")
			descriptor := add(fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"config":{"mediaType":%q,"digest":%q,"size":%d},"layers":[]}`, manifestType, config.MediaType, config.Digest, config.Size), manifestType)
			for level := range tt.depth {
				members := 1
				if level == 0 {
					members = tt.members
				}
				child := fmt.Sprintf(`{"mediaType":%q,"digest":%q,"size":%d}`, descriptor.MediaType, descriptor.Digest, descriptor.Size)
				children := strings.TrimSuffix(strings.Repeat(child+",", members), ",")
				descriptor = add(fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[%s]}`, indexType, children), indexType)
			}
			controls.ociIndex = []byte(fmt.Sprintf(`{"schemaVersion":2,"manifests":[{"mediaType":%q,"digest":%q,"size":%d,"annotations":{"org.opencontainers.image.ref.name":"mine/app:v1"}}]}`, descriptor.MediaType, descriptor.Digest, descriptor.Size))
			entries = append(entries, containerArchiveTestEntry{name: "index.json", body: string(controls.ociIndex)})
			t.Run("config collection", func(t *testing.T) {
				configs, unreadable := collectImageLoadConfigs(controls)
				labels, labelsUnreadable := imageLoadOwnerLabels(imageLoadArchiveInspection{configs: configs, configsUnreadable: unreadable}, ownerLabelTestKey)
				if tt.wantErr != "" {
					if !unreadable || !labelsUnreadable || len(labels) != 0 {
						t.Fatalf("over-budget configs readable: unreadable=%v labels=%v labelsUnreadable=%v", unreadable, labels, labelsUnreadable)
					}
				} else if unreadable || labelsUnreadable || !slices.Equal(labels, []string{"mine"}) {
					t.Fatalf("within-budget configs: unreadable=%v labels=%v labelsUnreadable=%v", unreadable, labels, labelsUnreadable)
				}
			})
			t.Run("archive validation", func(t *testing.T) {
				payload := mustContainerArchiveTar(t, entries...)
				archive, err := defaultIODeps().extractImageLoadArchiveFromTar(tar.NewReader(bytes.NewReader(payload)), false)
				if tt.wantErr != "" {
					if !errors.Is(err, errImageLoadOCIUninspectable) || !strings.Contains(err.Error(), tt.wantErr) {
						t.Fatalf("over-budget error=%v, want graph budget refusal", err)
					}
					return
				}
				labels, unreadable := imageLoadOwnerLabels(archive, ownerLabelTestKey)
				if err != nil || unreadable || !slices.Equal(labels, []string{"mine"}) {
					t.Fatalf("within-budget archive: error=%v unreadable=%v labels=%v", err, unreadable, labels)
				}
			})
		})
	}
}
