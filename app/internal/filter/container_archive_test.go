package filter

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
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

func TestContainerArchiveTargetQueryMatchesPodmanSemantics(t *testing.T) {
	payload := mustContainerArchiveTar(t, containerArchiveTestEntry{name: "file.txt", body: "ok"})
	tests := []struct {
		name       string
		query      string
		wantDeny   bool
		wantReason string
	}{
		{
			name:       "missing target",
			wantDeny:   true,
			wantReason: "target path is required",
		},
		{
			name:       "empty target",
			query:      "?path=",
			wantDeny:   true,
			wantReason: "target path is required",
		},
		{
			name:       "case folded unallowlisted target",
			query:      "?Path=/etc",
			wantDeny:   true,
			wantReason: "is not allowlisted",
		},
		{
			name:       "repeated target is ambiguous even when last is unallowlisted",
			query:      "?path=/app&path=/etc",
			wantDeny:   true,
			wantReason: "ambiguous path query",
		},
		{
			name:       "relative target cannot be resolved against an allowlist",
			query:      "?path=app",
			wantDeny:   true,
			wantReason: "is not allowlisted",
		},
		{
			name:       "case variant target keys are ambiguous",
			query:      "?path=/app&Path=/app",
			wantDeny:   true,
			wantReason: "ambiguous path query",
		},
		{
			name:  "single case folded target is accepted",
			query: "?Path=/app",
		},
		{
			name:       "repeated target is ambiguous even when last is allowlisted",
			query:      "?path=/etc&path=/app",
			wantDeny:   true,
			wantReason: "ambiguous path query",
		},
	}

	for _, surface := range []struct {
		name string
		path string
	}{
		{name: "docker", path: "/containers/abc/archive"},
		{name: "versioned docker", path: "/v1.45/containers/abc/archive"},
		{name: "libpod", path: "/libpod/containers/abc/archive"},
		{name: "versioned libpod", path: "/v5.0.0/libpod/containers/abc/archive"},
	} {
		for _, tt := range tests {
			t.Run(surface.name+"/"+tt.name, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodPut, surface.path+tt.query, bytes.NewReader(payload))
				reason, err := newContainerArchivePolicy(ContainerArchiveOptions{AllowedPaths: []string{"/app"}}).inspect(nil, req, NormalizePath(req.URL.Path))
				if err != nil {
					t.Fatalf("inspect() error = %v", err)
				}
				if tt.wantDeny {
					if !strings.Contains(reason, tt.wantReason) {
						t.Fatalf("reason = %q, want it to mention %q", reason, tt.wantReason)
					}
					return
				}
				if reason != "" {
					t.Fatalf("reason = %q, want allow", reason)
				}
				forwarded, err := io.ReadAll(req.Body)
				if err != nil {
					t.Fatalf("read replayed body: %v", err)
				}
				if err := req.Body.Close(); err != nil {
					t.Fatalf("close replayed body: %v", err)
				}
				if !bytes.Equal(forwarded, payload) {
					t.Fatal("forwarded body changed after archive inspection")
				}
			})
		}
	}
}

func TestContainerArchiveRenameQueryFailsClosed(t *testing.T) {
	payload := mustContainerArchiveTar(t, containerArchiveTestEntry{
		name: "dir/link",
		link: "../file",
		typ:  tar.TypeSymlink,
	})
	tests := []struct {
		name     string
		rawQuery string
		wantDeny bool
	}{
		{
			name:     "effective rename moves a safe link outside the target subtree",
			rawQuery: "path=/app&rename=" + url.QueryEscape(`{"dir/link":"link"}`),
			wantDeny: true,
		},
		{
			name:     "case folded effective rename is denied",
			rawQuery: "path=/app&Rename=" + url.QueryEscape(`{"dir/link":"link"}`),
			wantDeny: true,
		},
		{
			name:     "repeated rename is ambiguous when last is nonempty",
			rawQuery: "path=/app&rename=&rename=" + url.QueryEscape(`{"dir/link":"link"}`),
			wantDeny: true,
		},
		{
			name:     "case variant rename keys are ambiguous",
			rawQuery: "path=/app&rename=&Rename=",
			wantDeny: true,
		},
		{
			name:     "repeated rename is ambiguous even when last is empty",
			rawQuery: "path=/app&rename=" + url.QueryEscape(`{"dir/link":"link"}`) + "&rename=",
			wantDeny: true,
		},
		{
			name:     "single empty rename is a no-op",
			rawQuery: "path=/app&rename=",
		},
	}

	for _, surface := range []struct {
		name string
		path string
	}{
		{name: "docker", path: "/containers/abc/archive"},
		{name: "versioned docker", path: "/v1.45/containers/abc/archive"},
		{name: "libpod", path: "/libpod/containers/abc/archive"},
		{name: "versioned libpod", path: "/v5.0.0/libpod/containers/abc/archive"},
	} {
		for _, tt := range tests {
			t.Run(surface.name+"/"+tt.name, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodPut, surface.path+"?"+tt.rawQuery, bytes.NewReader(payload))
				reason, err := newContainerArchivePolicy(ContainerArchiveOptions{AllowedPaths: []string{"/app"}}).inspect(nil, req, NormalizePath(req.URL.Path))
				if err != nil {
					t.Fatalf("inspect() error = %v", err)
				}
				if tt.wantDeny {
					if !strings.Contains(reason, "rename query is not allowed") {
						t.Fatalf("reason = %q, want rename denial", reason)
					}
					return
				}
				if reason != "" {
					t.Fatalf("reason = %q, want allow", reason)
				}
				forwarded, err := io.ReadAll(req.Body)
				if err != nil {
					t.Fatalf("read replayed body: %v", err)
				}
				if err := req.Body.Close(); err != nil {
					t.Fatalf("close replayed body: %v", err)
				}
				if !bytes.Equal(forwarded, payload) {
					t.Fatal("forwarded body changed after empty effective rename")
				}
			})
		}
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

func TestContainerArchiveInspectSkipsNonArchiveRequestsAndNilBody(t *testing.T) {
	policy := newContainerArchivePolicy(ContainerArchiveOptions{})

	tests := []struct {
		name           string
		req            *http.Request
		normalizedPath string
	}{
		{name: "wrong path", req: httptest.NewRequest(http.MethodPut, "/containers/abc/json", strings.NewReader("tar")), normalizedPath: "/containers/abc/json"},
		{name: "nil body", req: func() *http.Request {
			req := httptest.NewRequest(http.MethodPut, "/containers/abc/archive?path=app", nil)
			req.Body = nil
			return req
		}(), normalizedPath: "/containers/abc/archive"},
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

func TestContainerArchiveDeniesUnallowlistedTargetPath(t *testing.T) {
	payload := mustContainerArchiveTar(t, containerArchiveTestEntry{name: "file.txt", body: "ok"})
	req := httptest.NewRequest(http.MethodPut, "/containers/abc/archive?path=etc", bytes.NewReader(payload))

	reason, err := newContainerArchivePolicy(ContainerArchiveOptions{AllowedPaths: []string{"app"}}).inspect(nil, req, "/containers/abc/archive")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != `container archive denied: target path "etc" is not allowlisted` {
		t.Fatalf("reason = %q", reason)
	}
}

func TestContainerArchiveEmptyBodyAllowedReturnsEmpty(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/containers/abc/archive?path=app", strings.NewReader(""))

	reason, err := newContainerArchivePolicy(ContainerArchiveOptions{}).inspect(nil, req, "/containers/abc/archive")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty", reason)
	}
}

func TestContainerArchiveReadErrorPropagates(t *testing.T) {
	sentinel := errors.New("read failed")
	req := httptest.NewRequest(http.MethodPut, "/containers/abc/archive?path=app", nil)
	req.Body = &readErrorReadCloser{readErr: sentinel}

	reason, err := newContainerArchivePolicy(ContainerArchiveOptions{}).inspect(nil, req, "/containers/abc/archive")
	if reason != "" {
		t.Fatalf("reason = %q, want empty", reason)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("inspect() error = %v, want wrapped %v", err, sentinel)
	}
}

func TestContainerArchiveInvalidTarReturnsInspectionError(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/containers/abc/archive?path=app", bytes.NewReader([]byte("not a tar archive")))

	reason, err := newContainerArchivePolicy(ContainerArchiveOptions{}).inspect(nil, req, "/containers/abc/archive")
	if reason != "" {
		t.Fatalf("reason = %q, want empty", reason)
	}
	if err == nil || !strings.Contains(err.Error(), "inspect archive body") {
		t.Fatalf("inspect() error = %v, want archive inspection error", err)
	}
}

func TestContainerArchiveRewindErrorAfterInspection(t *testing.T) {
	sentinel := errors.New("rewind failed")
	p := newContainerArchivePolicy(ContainerArchiveOptions{})
	oldSeekToStart := p.io.SeekToStart
	seekCalls := 0
	p.io.SeekToStart = func(file *os.File) error {
		seekCalls++
		if seekCalls == 2 {
			return sentinel
		}
		return oldSeekToStart(file)
	}

	payload := mustContainerArchiveTar(t, containerArchiveTestEntry{name: "file.txt", body: "ok"})
	req := httptest.NewRequest(http.MethodPut, "/containers/abc/archive?path=app", bytes.NewReader(payload))

	reason, err := p.inspect(nil, req, "/containers/abc/archive")
	if reason != "" {
		t.Fatalf("reason = %q, want empty", reason)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("inspect() error = %v, want wrapped %v", err, sentinel)
	}
}

func TestContainerArchivePathHelpersCoverEdgeCases(t *testing.T) {
	if isContainerArchivePath("/images/abc/archive") {
		t.Fatal("isContainerArchivePath() = true for non-container path")
	}

	if got, ok := normalizeContainerArchiveTargetPath("  "); !ok || got != "" {
		t.Fatalf("normalizeContainerArchiveTargetPath(blank) = %q, %v; want empty, true", got, ok)
	}
	if got, ok := normalizeContainerArchiveTargetPath("/"); !ok || got != "." {
		t.Fatalf("normalizeContainerArchiveTargetPath(/) = %q, %v; want ., true", got, ok)
	}

	for _, value := range []string{"/absolute", "../escape"} {
		if got, ok := normalizeContainerArchiveRelativePath(value); ok || got != "" {
			t.Fatalf("normalizeContainerArchiveRelativePath(%q) = %q, %v; want empty, false", value, got, ok)
		}
	}

	if reason := newContainerArchivePolicy(ContainerArchiveOptions{}).denyReasonForContainerArchiveEntry(nil); reason != "" {
		t.Fatalf("denyReasonForContainerArchiveEntry(nil) = %q, want empty", reason)
	}

	got := normalizeContainerArchiveAllowedPaths([]string{" ", "/app", "/app/uploads", "../etc", "app"})
	if len(got) != 1 || got[0] != "app" {
		t.Fatalf("normalizeContainerArchiveAllowedPaths() = %v, want [app]", got)
	}
}

func TestContainerArchiveLinkHelpersCoverEmptyAndAbsoluteTargets(t *testing.T) {
	if !containerArchiveSymlinkTargetIsSafe("link", "") {
		t.Fatal("empty symlink target should be safe")
	}
	if containerArchiveSymlinkTargetIsSafe("link", "/etc/passwd") {
		t.Fatal("absolute symlink target should be unsafe")
	}
	if !containerArchiveHardlinkTargetIsSafe("") {
		t.Fatal("empty hardlink target should be safe")
	}
}

func TestSpoolRequestBodyForInspectionEdgeCases(t *testing.T) {
	iod := defaultIODeps()
	spool, size, err := iod.spoolRequestBodyForInspection(nil, "sockguard-test-", 4)
	if err != nil {
		t.Fatalf("spoolRequestBodyForInspection(nil) error = %v", err)
	}
	if spool != nil || size != 0 {
		t.Fatalf("spoolRequestBodyForInspection(nil) = %#v, %d; want nil, 0", spool, size)
	}

	sentinel := errors.New("close failed")
	req := httptest.NewRequest(http.MethodPut, "/containers/abc/archive", nil)
	req.Body = &readErrorReadCloser{closeErr: sentinel}
	req.ContentLength = 5
	_, _, err = iod.spoolRequestBodyForInspection(req, "sockguard-test-", 4)
	if !errors.Is(err, sentinel) {
		t.Fatalf("spoolRequestBodyForInspection(close error) = %v, want %v", err, sentinel)
	}

	req = httptest.NewRequest(http.MethodPut, "/containers/abc/archive", strings.NewReader("12345"))
	req.ContentLength = -1
	_, size, err = iod.spoolRequestBodyForInspection(req, "sockguard-test-", 4)
	if !isBodyTooLargeError(err) {
		t.Fatalf("spoolRequestBodyForInspection(too large) error = %v, want bodyTooLargeError", err)
	}
	if size != 5 {
		t.Fatalf("size = %d, want 5", size)
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
