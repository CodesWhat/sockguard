package filter

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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

func mustImageLoadTar(t *testing.T, manifest string) []byte {
	t.Helper()

	return mustContainerArchiveTar(t,
		containerArchiveTestEntry{name: "manifest.json", body: manifest},
		containerArchiveTestEntry{name: "sha256/layer.tar", body: fmt.Sprintf("layer for %s", manifest)},
	)
}
