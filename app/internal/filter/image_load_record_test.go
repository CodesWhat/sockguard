package filter

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/logging"
)

// TestImageLoadRecordsWhatItReadForOwnership pins the handoff the owner
// isolation layer depends on: a load the inspector lets through leaves the
// names it read on the request metadata, and one it denies leaves nothing.
func TestImageLoadRecordsWhatItReadForOwnership(t *testing.T) {
	docker := mustImageLoadTar(t, `[{"RepoTags":["registry.example.com/acme/app:latest","acme/app:v1"]},{"RepoTags":null}]`)
	unknown := mustContainerArchiveTar(t, containerArchiveTestEntry{name: "repositories", body: `{"theirs/app":{"latest":"abc"}}`})

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
