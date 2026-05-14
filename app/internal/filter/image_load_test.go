package filter

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestImageLoadDeniedByDefault(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/images/load", strings.NewReader("image tar"))

	reason, err := newImageLoadPolicy(ImageLoadOptions{}).inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "image load denied: loading image archives is not allowed" {
		t.Fatalf("reason = %q", reason)
	}
}

func TestImageLoadAllowsWhenConfiguredAndPreservesBody(t *testing.T) {
	payload := mustImageLoadTar(t, `[{"RepoTags":["registry.example.com/acme/app:latest"]}]`)
	wantDigest := sha256.Sum256(payload)
	req := httptest.NewRequest(http.MethodPost, "/v1.45/images/load", strings.NewReader(string(payload)))

	reason, err := newImageLoadPolicy(ImageLoadOptions{AllowAllRegistries: true}).inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty", reason)
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if gotDigest := sha256.Sum256(body); gotDigest != wantDigest {
		t.Fatalf("body sha256 = %s, want %s", hex.EncodeToString(gotDigest[:]), hex.EncodeToString(wantDigest[:]))
	}
	if req.ContentLength != int64(len(payload)) {
		t.Fatalf("content length = %d, want %d", req.ContentLength, len(payload))
	}
}

func TestImageLoadDeniesUnallowlistedRegistry(t *testing.T) {
	payload := mustImageLoadTar(t, `[{"RepoTags":["registry.example.com/acme/app:latest"]}]`)
	req := httptest.NewRequest(http.MethodPost, "/images/load", strings.NewReader(string(payload)))

	reason, err := newImageLoadPolicy(ImageLoadOptions{AllowedRegistries: []string{"ghcr.io"}}).inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != `image load denied: registry "registry.example.com" is not allowlisted` {
		t.Fatalf("reason = %q", reason)
	}
}

func TestImageLoadDeniesUntaggedImagesByDefault(t *testing.T) {
	payload := mustImageLoadTar(t, `[{"RepoTags":[]}]`)
	req := httptest.NewRequest(http.MethodPost, "/images/load", strings.NewReader(string(payload)))

	reason, err := newImageLoadPolicy(ImageLoadOptions{AllowAllRegistries: true}).inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "image load denied: untagged images are not allowed" {
		t.Fatalf("reason = %q", reason)
	}
}

func TestImageLoadOversizedBodyReturnsRequestEntityTooLargeWhenAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/images/load", nil)
	req.Body = &readErrorReadCloser{readErr: io.ErrUnexpectedEOF}
	req.ContentLength = maxImageLoadBodyBytes + 1

	_, err := newImageLoadPolicy(ImageLoadOptions{AllowAllRegistries: true}).inspect(nil, req, NormalizePath(req.URL.Path))
	rejection, ok := requestRejectionFromError(err)
	if !ok {
		t.Fatalf("inspect() error = %v, want request rejection", err)
	}
	if rejection.status != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rejection.status, http.StatusRequestEntityTooLarge)
	}
	if !strings.HasPrefix(rejection.reason, "image load denied: request body exceeds") {
		t.Fatalf("reason = %q", rejection.reason)
	}
}

func TestImageLoadSkipsNonLoadRequestsAndNilBody(t *testing.T) {
	policy := newImageLoadPolicy(ImageLoadOptions{AllowAllRegistries: true})

	tests := []struct {
		name           string
		req            *http.Request
		normalizedPath string
	}{
		{name: "wrong path", req: httptest.NewRequest(http.MethodPost, "/images/create", strings.NewReader("image tar")), normalizedPath: "/images/create"},
		{name: "nil body", req: func() *http.Request {
			req := httptest.NewRequest(http.MethodPost, "/images/load", nil)
			req.Body = nil
			return req
		}(), normalizedPath: "/images/load"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason, err := policy.inspect(nil, tt.req, tt.normalizedPath)
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != "" {
				t.Fatalf("reason = %q, want empty", reason)
			}
		})
	}
}

func TestImageLoadEmptyBodyAllowedReturnsEmpty(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/images/load", strings.NewReader(""))

	reason, err := newImageLoadPolicy(ImageLoadOptions{AllowAllRegistries: true}).inspect(nil, req, "/images/load")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty", reason)
	}
}

func TestImageLoadReadErrorPropagates(t *testing.T) {
	sentinel := errors.New("read failed")
	req := httptest.NewRequest(http.MethodPost, "/images/load", nil)
	req.Body = &readErrorReadCloser{readErr: sentinel}

	reason, err := newImageLoadPolicy(ImageLoadOptions{AllowAllRegistries: true}).inspect(nil, req, "/images/load")
	if reason != "" {
		t.Fatalf("reason = %q, want empty", reason)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("inspect() error = %v, want wrapped %v", err, sentinel)
	}
}

func TestImageLoadInvalidArchiveReturnsInspectionError(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/images/load", bytes.NewReader([]byte("not a tar archive")))

	reason, err := newImageLoadPolicy(ImageLoadOptions{AllowAllRegistries: true}).inspect(nil, req, "/images/load")
	if reason != "" {
		t.Fatalf("reason = %q, want empty", reason)
	}
	if err == nil || !strings.Contains(err.Error(), "inspect image load manifest") {
		t.Fatalf("inspect() error = %v, want manifest inspection error", err)
	}
}

func TestImageLoadDeniesMissingManifestUnlessUntaggedAllowed(t *testing.T) {
	payload := mustContainerArchiveTar(t, containerArchiveTestEntry{name: "sha256/layer.tar", body: "layer"})
	req := httptest.NewRequest(http.MethodPost, "/images/load", bytes.NewReader(payload))

	reason, err := newImageLoadPolicy(ImageLoadOptions{AllowAllRegistries: true}).inspect(nil, req, "/images/load")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "image load denied: image manifest is not inspectable" {
		t.Fatalf("reason = %q", reason)
	}

	req = httptest.NewRequest(http.MethodPost, "/images/load", bytes.NewReader(payload))
	reason, err = newImageLoadPolicy(ImageLoadOptions{AllowUntagged: true}).inspect(nil, req, "/images/load")
	if err != nil {
		t.Fatalf("inspect() with AllowUntagged error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason with AllowUntagged = %q, want empty", reason)
	}
}

func TestImageLoadRewindErrorAfterInspection(t *testing.T) {
	sentinel := errors.New("rewind failed")
	p := newImageLoadPolicy(ImageLoadOptions{AllowAllRegistries: true})
	oldSeekToStart := p.io.SeekToStart
	seekCalls := 0
	p.io.SeekToStart = func(file *os.File) error {
		seekCalls++
		if seekCalls == 2 {
			return sentinel
		}
		return oldSeekToStart(file)
	}

	payload := mustImageLoadTar(t, `[{"RepoTags":["registry.example.com/acme/app:latest"]}]`)
	req := httptest.NewRequest(http.MethodPost, "/images/load", bytes.NewReader(payload))

	reason, err := p.inspect(nil, req, "/images/load")
	if reason != "" {
		t.Fatalf("reason = %q, want empty", reason)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("inspect() error = %v, want wrapped %v", err, sentinel)
	}
}

func TestImageLoadDenyReasonForTagEdgeCases(t *testing.T) {
	if got := newImageLoadPolicy(ImageLoadOptions{}).denyReasonForTag(" <none>:<none> "); got != "image load denied: untagged images are not allowed" {
		t.Fatalf("denyReasonForTag(<none>) = %q", got)
	}
	if got := newImageLoadPolicy(ImageLoadOptions{AllowUntagged: true}).denyReasonForTag(" "); got != "" {
		t.Fatalf("denyReasonForTag(blank) with AllowUntagged = %q, want empty", got)
	}

	got := newImageLoadPolicy(ImageLoadOptions{AllowAllRegistries: true}).denyReasonForTag("registry.example.com//app:latest")
	if got != `image load denied: image reference "registry.example.com//app:latest" could not be inspected` {
		t.Fatalf("denyReasonForTag(invalid) = %q", got)
	}
}

func TestExtractImageLoadRepoTagsManifestErrors(t *testing.T) {
	t.Run("read manifest error", func(t *testing.T) {
		sentinel := errors.New("read manifest failed")
		iod := defaultIODeps()
		iod.ReadAllLimited = func(io.Reader, int64) ([]byte, error) {
			return nil, sentinel
		}

		_, _, err := iod.extractImageLoadRepoTags(bytes.NewReader(mustImageLoadTar(t, `[]`)))
		if !errors.Is(err, sentinel) {
			t.Fatalf("extractImageLoadRepoTags() error = %v, want wrapped %v", err, sentinel)
		}
	})

	t.Run("manifest too large", func(t *testing.T) {
		iod := defaultIODeps()
		iod.ReadAllLimited = func(io.Reader, int64) ([]byte, error) {
			return bytes.Repeat([]byte{'x'}, maxImageLoadManifestBytes+1), nil
		}

		_, _, err := iod.extractImageLoadRepoTags(bytes.NewReader(mustImageLoadTar(t, `[]`)))
		if err == nil || !strings.Contains(err.Error(), "manifest.json exceeds") {
			t.Fatalf("extractImageLoadRepoTags() error = %v, want manifest size error", err)
		}
	})

	t.Run("decode manifest error", func(t *testing.T) {
		_, _, err := defaultIODeps().extractImageLoadRepoTags(bytes.NewReader(mustImageLoadTar(t, `{`)))
		if err == nil || !strings.Contains(err.Error(), "decode manifest.json") {
			t.Fatalf("extractImageLoadRepoTags() error = %v, want decode error", err)
		}
	})
}

func TestNormalizeImageLoadArchivePath(t *testing.T) {
	tests := []struct {
		value string
		want  string
	}{
		{value: "  ", want: ""},
		{value: "/", want: ""},
		{value: "/manifest.json", want: "manifest.json"},
	}

	for _, tt := range tests {
		if got := normalizeImageLoadArchivePath(tt.value); got != tt.want {
			t.Fatalf("normalizeImageLoadArchivePath(%q) = %q, want %q", tt.value, got, tt.want)
		}
	}
}

func mustImageLoadTar(t *testing.T, manifest string) []byte {
	t.Helper()

	return mustContainerArchiveTar(t,
		containerArchiveTestEntry{name: "manifest.json", body: manifest},
		containerArchiveTestEntry{name: "sha256/layer.tar", body: fmt.Sprintf("layer for %s", manifest)},
	)
}
