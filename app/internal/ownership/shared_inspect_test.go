package ownership

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/dockerresource"
	"github.com/codeswhat/sockguard/v3/app/internal/logging"
	"github.com/codeswhat/sockguard/v3/app/internal/visibility"
)

// countingDaemon is an http.RoundTripper standing in for the Docker daemon. It
// records every request path it serves.
type countingDaemon struct {
	mu    sync.Mutex
	paths []string
}

func (d *countingDaemon) RoundTrip(r *http.Request) (*http.Response, error) {
	d.mu.Lock()
	d.paths = append(d.paths, r.Method+" "+r.URL.Path)
	d.mu.Unlock()
	body := `{"Config":{"Labels":{"env":"prod","com.sockguard.owner":"job-123"}},"Name":"/web","Image":"sha256:abc"}`
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    r,
	}, nil
}

func (d *countingDaemon) count(path string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, p := range d.paths {
		if p == path {
			n++
		}
	}
	return n
}

func TestVisibilityAndOwnershipShareOneInspectPerRequest(t *testing.T) {
	t.Parallel()
	daemon := &countingDaemon{}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The proxied call itself, as the daemon would see it.
		if _, err := daemon.RoundTrip(r); err != nil {
			t.Errorf("proxied call: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	})
	owned := MiddlewareWithRoundTripper(daemon, testLogger(), Options{Owner: "job-123", LabelKey: "com.sockguard.owner"})(next)
	handler := visibility.MiddlewareWithRoundTripper(daemon, testLogger(), visibility.Options{VisibleResourceLabels: []string{"env=prod"}})(owned)

	req := httptest.NewRequest(http.MethodGet, "/containers/web/json", nil)
	req = req.WithContext(logging.WithMeta(req.Context(), &logging.RequestMeta{}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	// One shared inspect plus the proxied call itself.
	if got := daemon.count("GET /containers/web/json"); got != 2 {
		t.Fatalf("daemon saw %d GET /containers/web/json, want 2 (one inspect + the proxied call); paths: %v", got, daemon.paths)
	}
}

func TestOwnershipInspectsWhenNothingWasRecorded(t *testing.T) {
	t.Parallel()
	daemon := &countingDaemon{}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := MiddlewareWithRoundTripper(daemon, testLogger(), Options{Owner: "job-123", LabelKey: "com.sockguard.owner"})(next)

	req := httptest.NewRequest(http.MethodGet, "/containers/web/json", nil)
	req = req.WithContext(logging.WithMeta(req.Context(), &logging.RequestMeta{}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if got := daemon.count("GET /containers/web/json"); got != 1 {
		t.Fatalf("daemon saw %d inspects, want 1; paths: %v", got, daemon.paths)
	}
}

func TestReuseRequestInspectSkipsMemoForExactSecretLookup(t *testing.T) {
	t.Parallel()
	meta := &logging.RequestMeta{}
	meta.RecordInspectedLabels(string(dockerresource.KindSecret), "X", map[string]string{"com.sockguard.owner": "job-123"}, true)
	ctx := logging.WithMeta(context.Background(), meta)

	var dials int
	inspect := reuseRequestInspect(func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error) {
		dials++
		return nil, false, nil
	})

	// A plain (prefix-capable) secret lookup reuses what visibility recorded.
	if labels, found, err := inspect(ctx, dockerresource.KindSecret, "X"); err != nil || !found || labels["com.sockguard.owner"] != "job-123" || dials != 0 {
		t.Fatalf("plain lookup = %v, %v, %v, dials %d; want the recorded result and no dial", labels, found, err, dials)
	}
	// An embedded exact reference to the same secret must do its own lookup.
	if _, found, err := inspect(withExactSecretLookup(ctx), dockerresource.KindSecret, "X"); err != nil || found || dials != 1 {
		t.Fatalf("exact lookup = found %v, err %v, dials %d; want its own dial", found, err, dials)
	}
	// Other kinds keep reusing the memo even under an exact-secret context.
	meta.RecordInspectedLabels(string(dockerresource.KindContainer), "web", map[string]string{"a": "b"}, true)
	if _, found, _ := inspect(withExactSecretLookup(ctx), dockerresource.KindContainer, "web"); !found || dials != 1 {
		t.Fatalf("container lookup dialed (dials %d)", dials)
	}
}
