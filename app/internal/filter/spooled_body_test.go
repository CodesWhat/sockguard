package filter

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

// spooledBodyFiles lists what is left in the directory request bodies are
// spooled to.
func spooledBodyFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read spool directory: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

// TestMiddlewareRemovesTheBodyItSpooled covers every route whose inspector
// spools the request body to a temp file and hands the file on as r.Body.
//
// The file used to be removed only by a Close on that body, which the reverse
// proxy calls and nothing else does. A layer between the filter and the proxy
// that answered the request itself (owner isolation refusing it, or failing
// its lookup) returned without one, and the file stayed on disk: up to the
// route's body limit for each such request. The filter put the file there, so
// the filter removes it once the rest of the chain has returned.
func TestMiddlewareRemovesTheBodyItSpooled(t *testing.T) {
	routes := []struct {
		name   string
		method string
		target string
		cfg    PolicyConfig
		body   []byte
	}{
		{
			name: "image load", method: http.MethodPost, target: "/v1.45/images/load",
			cfg:  PolicyConfig{ImageLoad: ImageLoadOptions{AllowAllRegistries: true}},
			body: mustImageLoadTar(t, `[{"RepoTags":["acme/app:v1"]}]`),
		},
		{
			name: "libpod image load", method: http.MethodPost, target: "/v5.0.0/libpod/images/load",
			cfg:  PolicyConfig{ImageLoad: ImageLoadOptions{AllowAllRegistries: true}},
			body: mustImageLoadTar(t, `[{"RepoTags":["registry.example.com/acme/app:v1"]}]`),
		},
		{
			// RUN is restricted by default, which is what has the filter open
			// the context.
			name: "build context", method: http.MethodPost, target: "/v1.45/build?t=acme%2Fapp",
			body: mustBuildContextTar(t, "Dockerfile", "FROM scratch\nCOPY . /app\n"),
		},
		{
			name: "container archive", method: http.MethodPut, target: "/v1.45/containers/abc/archive?path=%2Ftmp",
			body: mustContainerArchiveTar(t, containerArchiveTestEntry{name: "file.txt", body: "hello"}),
		},
		{
			name: "plugin create", method: http.MethodPost, target: "/v1.45/plugins/create?name=acme%2Fplugin",
			body: mustPluginCreateContextTar(t, pluginCreateConfig{}, false),
		},
		{
			name: "libpod image import", method: http.MethodPost, target: "/v5.0.0/libpod/images/import",
			cfg:  PolicyConfig{ImagePull: ImagePullOptions{AllowImports: true}},
			body: mustContainerArchiveTar(t, containerArchiveTestEntry{name: "etc/hostname", body: "imported"}),
		},
	}

	downstream := []struct {
		name string
		// serve is the rest of the chain. It reports the body it read, or nil
		// when it read none.
		serve     func(http.ResponseWriter, *http.Request) []byte
		wantPanic bool
	}{
		{
			name: "answers without touching the body",
			serve: func(w http.ResponseWriter, _ *http.Request) []byte {
				w.WriteHeader(http.StatusForbidden)
				return nil
			},
		},
		{
			name: "reads the body and leaves it open",
			serve: func(w http.ResponseWriter, r *http.Request) []byte {
				body, _ := io.ReadAll(r.Body)
				w.WriteHeader(http.StatusOK)
				return body
			},
		},
		{
			// What the reverse proxy does: it closes the outbound body itself,
			// so the filter's close is the second one.
			name: "reads the body and closes it",
			serve: func(w http.ResponseWriter, r *http.Request) []byte {
				body, _ := io.ReadAll(r.Body)
				if err := r.Body.Close(); err != nil {
					t.Errorf("downstream Close() error = %v", err)
				}
				w.WriteHeader(http.StatusOK)
				return body
			},
		},
		{
			name:      "panics",
			serve:     func(http.ResponseWriter, *http.Request) []byte { panic(http.ErrAbortHandler) },
			wantPanic: true,
		},
	}

	for _, route := range routes {
		for _, next := range downstream {
			t.Run(route.name+"/"+next.name, func(t *testing.T) {
				dir := t.TempDir()
				t.Setenv("TMPDIR", dir)

				allow, err := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionAllow, Index: 0})
				if err != nil {
					t.Fatalf("compile rule: %v", err)
				}
				var (
					reached bool
					spooled []string
					read    []byte
				)
				handler := MiddlewareWithOptions([]*CompiledRule{allow}, testLogger(), Options{PolicyConfig: route.cfg})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					reached = true
					spooled = spooledBodyFiles(t, dir)
					read = next.serve(w, r)
				}))

				req := httptest.NewRequest(route.method, route.target, bytes.NewReader(route.body))
				rec := httptest.NewRecorder()
				func() {
					defer func() {
						if recovered := recover(); (recovered != nil) != next.wantPanic {
							t.Errorf("recovered %v, want a panic = %v", recovered, next.wantPanic)
						}
					}()
					handler.ServeHTTP(rec, req)
				}()

				if !reached {
					t.Fatalf("the request never left the filter: status %d, body %s", rec.Code, rec.Body.String())
				}
				// The control: without a spooled body in flight the rest of the
				// test would pass on a route that never spooled one.
				if len(spooled) != 1 {
					t.Fatalf("spool directory held %v while the chain ran, want one spooled body", spooled)
				}
				if read != nil && !bytes.Equal(read, route.body) {
					t.Errorf("downstream read %d bytes, want the %d the client sent", len(read), len(route.body))
				}
				if left := spooledBodyFiles(t, dir); len(left) != 0 {
					t.Errorf("spool directory holds %v after the chain returned, want it empty", left)
				}
			})
		}
	}
}

// TestTempFileBodyCloseIsIdempotent pins what lets the filter close a body the
// reverse proxy and the upstream transport may already have closed, possibly
// from another goroutine: the file is closed and removed once, and every later
// Close reports what the first one did. A second removal could otherwise take
// a file another request has since been handed under the same name.
func TestTempFileBodyCloseIsIdempotent(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "sockguard-tempclose-twice-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	var (
		mu      sync.Mutex
		removed []string
	)
	iod := defaultIODeps()
	iod.RemoveFilePath = func(name string) error {
		mu.Lock()
		defer mu.Unlock()
		removed = append(removed, name)
		return os.Remove(name)
	}
	body := &tempFileBody{file: file, path: file.Name(), io: iod, content: io.NewSectionReader(file, 0, 0)}

	const closers = 8
	errs := make([]error, closers)
	var wg sync.WaitGroup
	for i := range closers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = body.Close()
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("Close() #%d error = %v, want nil", i, err)
		}
	}
	if len(removed) != 1 || removed[0] != file.Name() {
		t.Errorf("removed %v, want %s removed once", removed, file.Name())
	}
	if _, err := os.Stat(file.Name()); !os.IsNotExist(err) {
		t.Errorf("stat after Close() = %v, want the file gone", err)
	}
	if _, err := body.Read(make([]byte, 1)); err == nil {
		t.Error("Read() after Close() succeeded, want an error")
	}
}

// TestCloseSpooledRequestBodyReportsAFileItCouldNotRemove covers the one way
// a spooled body can still be left behind: the removal itself failing. That
// is logged, so a temp directory filling up has a line to explain it. A body
// the filter did not spool is not its to close.
func TestCloseSpooledRequestBodyReportsAFileItCouldNotRemove(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "sockguard-tempclose-warn-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	iod := defaultIODeps()
	iod.RemoveFilePath = func(string) error { return errors.New("remove failed") }

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
	req := httptest.NewRequest(http.MethodPost, "/images/load", nil)
	req.Body = &tempFileBody{file: file, path: file.Name(), io: iod}

	remove := closeSpooledRequestBody(logger, req)
	if remove == nil {
		t.Fatal("closeSpooledRequestBody() = nil for a spooled body")
	}
	remove()
	if got := logs.String(); !strings.Contains(got, "failed to remove spooled request body") || !strings.Contains(got, "remove failed") {
		t.Errorf("log = %q, want the failed removal reported", got)
	}

	req.Body = io.NopCloser(strings.NewReader("not spooled"))
	if closeSpooledRequestBody(logger, req) != nil {
		t.Error("closeSpooledRequestBody() returned a close for a body the filter did not spool")
	}
}
