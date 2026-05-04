package filter

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestContainerArchiveDeniesUnsafeTargetPath(t *testing.T) {
	tests := []struct {
		name   string
		target string
	}{
		{name: "parent", target: "../etc"},
		{name: "parent after clean", target: "app/../../etc"},
		{name: "encoded parent", target: "%2e%2e%2fetc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "/containers/abc/archive?path="+tt.target, bytes.NewReader(mustContainerArchiveTar(t, containerArchiveTestEntry{name: "app/file.txt", body: "ok"})))

			reason, err := newContainerArchivePolicy(ContainerArchiveOptions{}).inspect(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != "container archive denied: target path must stay within the container path" {
				t.Fatalf("reason = %q", reason)
			}
		})
	}
}

func TestContainerArchiveAllowsAbsoluteContainerTargetPath(t *testing.T) {
	payload := mustContainerArchiveTar(t, containerArchiveTestEntry{name: "file.txt", body: "ok"})
	req := httptest.NewRequest(http.MethodPut, "/containers/abc/archive?path=/app/uploads", bytes.NewReader(payload))

	reason, err := newContainerArchivePolicy(ContainerArchiveOptions{
		AllowedPaths: []string{"/app"},
	}).inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty", reason)
	}
}

func TestContainerArchiveDeniesUnsafeTarEntries(t *testing.T) {
	tests := []struct {
		name       string
		entry      containerArchiveTestEntry
		wantReason string
	}{
		{
			name:       "absolute entry",
			entry:      containerArchiveTestEntry{name: "/etc/passwd", body: "root"},
			wantReason: `container archive denied: tar entry "/etc/passwd" must be relative and stay within the archive`,
		},
		{
			name:       "parent entry",
			entry:      containerArchiveTestEntry{name: "../etc/passwd", body: "root"},
			wantReason: `container archive denied: tar entry "../etc/passwd" must be relative and stay within the archive`,
		},
		{
			name:       "setuid entry",
			entry:      containerArchiveTestEntry{name: "bin/tool", body: "x", mode: 0o4755},
			wantReason: `container archive denied: tar entry "bin/tool" sets setuid/setgid bits`,
		},
		{
			name:       "device node",
			entry:      containerArchiveTestEntry{name: "dev/kvm", typ: tar.TypeChar, mode: 0o600},
			wantReason: `container archive denied: tar entry "dev/kvm" is a device node`,
		},
		{
			name:       "symlink escape",
			entry:      containerArchiveTestEntry{name: "link", link: "../etc/passwd", typ: tar.TypeSymlink},
			wantReason: `container archive denied: symlink "link" escapes the archive`,
		},
		{
			name:       "hardlink escape",
			entry:      containerArchiveTestEntry{name: "link", link: "../etc/passwd", typ: tar.TypeLink},
			wantReason: `container archive denied: hardlink "link" escapes the archive`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "/containers/abc/archive?path=app", bytes.NewReader(mustContainerArchiveTar(t, tt.entry)))

			reason, err := newContainerArchivePolicy(ContainerArchiveOptions{}).inspect(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != tt.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

func TestContainerArchiveAllowsSafeTarAndPreservesBody(t *testing.T) {
	payload := mustContainerArchiveTar(t,
		containerArchiveTestEntry{name: "app/file.txt", body: "hello"},
		containerArchiveTestEntry{name: "app/current", link: "file.txt", typ: tar.TypeSymlink},
	)
	wantDigest := sha256.Sum256(payload)
	req := httptest.NewRequest(http.MethodPut, "/v1.45/containers/abc/archive?path=app", bytes.NewReader(payload))

	reason, err := newContainerArchivePolicy(ContainerArchiveOptions{}).inspect(nil, req, NormalizePath(req.URL.Path))
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

func TestContainerArchiveOversizedBodyReturnsRequestEntityTooLarge(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/containers/abc/archive?path=app", nil)
	req.Body = &readErrorReadCloser{readErr: io.ErrUnexpectedEOF}
	req.ContentLength = maxContainerArchiveBodyBytes + 1

	_, err := newContainerArchivePolicy(ContainerArchiveOptions{}).inspect(nil, req, NormalizePath(req.URL.Path))
	rejection, ok := requestRejectionFromError(err)
	if !ok {
		t.Fatalf("inspect() error = %v, want request rejection", err)
	}
	if rejection.status != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rejection.status, http.StatusRequestEntityTooLarge)
	}
	if !strings.HasPrefix(rejection.reason, "container archive denied: request body exceeds") {
		t.Fatalf("reason = %q", rejection.reason)
	}
}

type containerArchiveTestEntry struct {
	name string
	body string
	link string
	typ  byte
	mode int64
}

func mustContainerArchiveTar(t *testing.T, entries ...containerArchiveTestEntry) []byte {
	t.Helper()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, entry := range entries {
		typ := entry.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		mode := entry.mode
		if mode == 0 {
			mode = 0o644
		}
		header := &tar.Header{
			Name:     entry.name,
			Mode:     mode,
			Typeflag: typ,
			Linkname: entry.link,
		}
		if typ == tar.TypeReg {
			header.Size = int64(len(entry.body))
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatalf("write tar header: %v", err)
		}
		if typ == tar.TypeReg && entry.body != "" {
			if _, err := tw.Write([]byte(entry.body)); err != nil {
				t.Fatalf("write tar body: %v", err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	return buf.Bytes()
}
