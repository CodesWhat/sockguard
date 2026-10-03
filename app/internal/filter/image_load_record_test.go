package filter

import (
	"archive/tar"
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/logging"
)

// TestImageLoadRecordsWhatItReadForOwnership pins the handoff the owner
// isolation layer depends on: a load the inspector lets through leaves the
// names it read on the request metadata, and one it denies leaves nothing.
func TestImageLoadRecordsWhatItReadForOwnership(t *testing.T) {
	docker := mustImageLoadTar(t, `[{"RepoTags":["registry.example.com/acme/app:latest","acme/app:v1"]},{"RepoTags":null}]`)
	unknown := mustContainerArchiveTar(t, containerArchiveTestEntry{name: "layer.tar", body: "layer"})

	tests := []struct {
		name       string
		path       string
		opts       ImageLoadOptions
		body       io.Reader
		wantDenied bool
		want       *logging.ImageLoadRecord
	}{
		{
			name: "docker archive", path: "/v1.45/images/load", opts: ImageLoadOptions{AllowAllRegistries: true, AllowUntagged: true}, body: bytes.NewReader(docker),
			want: &logging.ImageLoadRecord{References: []string{"registry.example.com/acme/app:latest", "acme/app:v1"}},
		},
		{
			name: "docker archive on the native route keeps the names as spelled", path: "/v5.0.0/libpod/images/load", opts: ImageLoadOptions{AllowAllRegistries: true, AllowUntagged: true}, body: bytes.NewReader(docker),
			want: &logging.ImageLoadRecord{References: []string{"registry.example.com/acme/app:latest", "acme/app:v1"}},
		},
		{
			name: "archive in neither format under allow_untagged", path: "/images/load", opts: ImageLoadOptions{AllowUntagged: true}, body: bytes.NewReader(unknown),
			want: &logging.ImageLoadRecord{Unreadable: true},
		},
		{name: "empty body", path: "/images/load", opts: ImageLoadOptions{AllowAllRegistries: true}, body: bytes.NewReader(nil), want: &logging.ImageLoadRecord{}},
		{name: "denied registry", path: "/images/load", opts: ImageLoadOptions{AllowOfficial: true, AllowUntagged: true}, body: bytes.NewReader(docker), wantDenied: true},
		{name: "loads not allowed", path: "/images/load", body: bytes.NewReader(docker), wantDenied: true},
		{name: "host path load", path: "/v5.0.0/libpod/local/images/load", opts: ImageLoadOptions{AllowBlindWrites: true}, body: bytes.NewReader(nil)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta := &logging.RequestMeta{}
			req := httptest.NewRequest(http.MethodPost, tt.path, tt.body)
			req = req.WithContext(logging.WithMeta(req.Context(), meta))

			reason, err := newImageLoadPolicy(tt.opts).inspect(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if denied := reason != ""; denied != tt.wantDenied {
				t.Fatalf("reason = %q, want denied = %v", reason, tt.wantDenied)
			}
			got := meta.ImageLoad
			switch {
			case tt.want == nil && got != nil:
				t.Fatalf("record = %+v, want none", got)
			case tt.want == nil:
			case got == nil:
				t.Fatalf("record = nil, want %+v", tt.want)
			case got.Unreadable != tt.want.Unreadable || !slices.Equal(got.References, tt.want.References):
				t.Fatalf("record = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestImageLoadRecordNeedsRequestMetadata covers a caller outside the
// middleware chain: with no metadata on the context there is nowhere to leave
// a record, and the inspection still runs.
func TestImageLoadRecordNeedsRequestMetadata(t *testing.T) {
	payload := mustImageLoadTar(t, `[{"RepoTags":["acme/app:v1"]}]`)
	req := httptest.NewRequest(http.MethodPost, "/images/load", bytes.NewReader(payload))

	reason, err := newImageLoadPolicy(ImageLoadOptions{AllowAllRegistries: true}).inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil || reason != "" {
		t.Fatalf("inspect() = %q, %v, want the load allowed", reason, err)
	}
}

// TestImageLoadReadsNoNamesFromALegacyRepositoriesFile covers the one place a
// daemon takes image names from a file this inspector does not read.
//
// moby's classic image store, up to 28.x, loads an archive with no
// manifest.json in its pre-1.10 layout: every top-level directory holding
// `json` and `layer.tar` is an image, and a top-level `repositories` file names
// them. An index.json beside that changes nothing for the daemon, but it had
// this inspector class the archive as OCI and check only the index's names, so
// the names the daemon went on to assign were never looked at: not against the
// registry allowlist here, and not by owner isolation. Read from moby 28.5.1
// (image/tarexport/load.go). 29.0 dropped the fallback, and neither a
// containerd-store dockerd nor Podman ever reads the file.
//
// With a manifest.json in the archive the daemon reads that and ignores
// `repositories`, which is what every `docker save` since 1.10 writes, so
// those archives are checked by their manifest names as before.
func TestImageLoadReadsNoNamesFromALegacyRepositoriesFile(t *testing.T) {
	const legacyDeny = "image load denied: archive names images in a legacy repositories file that is not inspected"
	repositories := containerArchiveTestEntry{name: "repositories", body: `{"evil.example/theirs/app":{"latest":"blobs"}}`}
	legacyImage := []containerArchiveTestEntry{
		{name: "blobs/json", body: `{"id":"blobs","os":"linux"}`},
		{name: "blobs/layer.tar", body: "layer"},
	}
	ociName := "registry.example.com/acme/app:v1"
	oci := mustOCIImageLoadEntries(t, ociName)
	docker := []containerArchiveTestEntry{{name: "manifest.json", body: `[{"RepoTags":["registry.example.com/acme/app:v1"]}]`}}

	archive := func(groups ...[]containerArchiveTestEntry) []byte {
		var entries []containerArchiveTestEntry
		for _, group := range groups {
			entries = append(entries, group...)
		}
		return mustContainerArchiveTar(t, entries...)
	}
	allowlist := ImageLoadOptions{AllowedRegistries: []string{"registry.example.com"}}
	allowAll := ImageLoadOptions{AllowAllRegistries: true}

	tests := []struct {
		name       string
		path       string
		opts       ImageLoadOptions
		body       []byte
		wantReason string
		want       *logging.ImageLoadRecord
	}{
		{
			name: "beside an OCI index under a registry allowlist", path: "/v1.45/images/load", opts: allowlist,
			body: archive(oci, legacyImage, []containerArchiveTestEntry{repositories}), wantReason: legacyDeny,
		},
		{
			name: "beside an OCI index with every registry allowed", path: "/v1.45/images/load", opts: allowAll,
			body: archive(oci, legacyImage, []containerArchiveTestEntry{repositories}),
			want: &logging.ImageLoadRecord{References: []string{ociName}, LegacyNames: true},
		},
		{
			name: "ahead of the OCI index", path: "/images/load", opts: allowlist,
			body: archive([]containerArchiveTestEntry{repositories}, legacyImage, oci), wantReason: legacyDeny,
		},
		{
			name: "under another spelling of the path", path: "/images/load", opts: allowlist,
			body: archive(oci, legacyImage, []containerArchiveTestEntry{{name: "./x/../repositories", body: repositories.body}}), wantReason: legacyDeny,
		},
		{
			name: "as a directory", path: "/images/load", opts: allowlist,
			body: archive(oci, []containerArchiveTestEntry{{name: "repositories/", typ: tar.TypeDir, mode: 0o755}}), wantReason: legacyDeny,
		},
		{
			// Podman reads manifest.json or index.json and nothing else, so
			// its native route has no names to miss.
			name: "on the native route", path: "/v5.0.0/libpod/images/load", opts: allowlist,
			body: archive(oci, legacyImage, []containerArchiveTestEntry{repositories}),
			want: &logging.ImageLoadRecord{References: []string{ociName}, LegacyNames: true},
		},
		{
			name: "in an archive with nothing else under allow_untagged", path: "/images/load", opts: ImageLoadOptions{AllowedRegistries: []string{"registry.example.com"}, AllowUntagged: true},
			body: archive(legacyImage, []containerArchiveTestEntry{repositories}), wantReason: legacyDeny,
		},
		{
			name: "in an archive with nothing else and every registry allowed", path: "/images/load", opts: ImageLoadOptions{AllowAllRegistries: true, AllowUntagged: true},
			body: archive(legacyImage, []containerArchiveTestEntry{repositories}),
			want: &logging.ImageLoadRecord{Unreadable: true, LegacyNames: true},
		},
		{
			name: "beside manifest.json", path: "/v1.45/images/load", opts: allowlist,
			body: archive(docker, []containerArchiveTestEntry{repositories}),
			want: &logging.ImageLoadRecord{References: []string{ociName}},
		},
		{
			name: "beside manifest.json and an OCI index", path: "/v1.45/images/load", opts: allowlist,
			body: archive(oci, docker, []containerArchiveTestEntry{repositories}),
			want: &logging.ImageLoadRecord{References: []string{ociName, ociName}},
		},
		{
			name: "nested below the archive root", path: "/v1.45/images/load", opts: allowlist,
			body: archive(oci, []containerArchiveTestEntry{{name: "docs/repositories", body: repositories.body}}),
			want: &logging.ImageLoadRecord{References: []string{ociName}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TMPDIR", t.TempDir())
			meta := &logging.RequestMeta{}
			req := httptest.NewRequest(http.MethodPost, tt.path, bytes.NewReader(tt.body))
			req = req.WithContext(logging.WithMeta(req.Context(), meta))

			reason, err := newImageLoadPolicy(tt.opts).inspect(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != tt.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tt.wantReason)
			}
			got := meta.ImageLoad
			switch {
			case tt.want == nil && got != nil:
				t.Fatalf("record = %+v, want none", got)
			case tt.want == nil:
			case got == nil:
				t.Fatalf("record = nil, want %+v", tt.want)
			case got.Unreadable != tt.want.Unreadable || got.LegacyNames != tt.want.LegacyNames || !slices.Equal(got.References, tt.want.References):
				t.Fatalf("record = %+v, want %+v", got, tt.want)
			}
		})
	}
}
