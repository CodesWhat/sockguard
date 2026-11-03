package ownership

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/logging"
)

// pullMockDaemon is the upstream a pull's post-check talks to: it answers an
// image inspect from a label table and records each untag.
type pullMockDaemon struct {
	mu     sync.Mutex
	labels map[string]map[string]string // reference -> labels; absent means not found
	// written is what the pull puts in the store when the upstream handler
	// runs. Until then the names are free, which the request-side check needs.
	written     map[string]map[string]string
	pulled      bool
	inspectFail map[string]bool
	untagFail   bool
	untagged    []string
	requests    []string
}

func (d *pullMockDaemon) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	d.mu.Lock()
	defer d.mu.Unlock()
	d.requests = append(d.requests, req.Method+" "+req.URL.Path)
	switch {
	case req.Method == http.MethodGet && strings.HasSuffix(req.URL.Path, "/json"):
		ref := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(req.URL.Path, "/libpod"), "/images/"), "/json")
		switch labels, ok := d.labels[ref]; {
		case d.pulled && d.inspectFail[ref]:
			rec.WriteHeader(http.StatusInternalServerError)
		case !ok:
			rec.WriteHeader(http.StatusNotFound)
		default:
			var pairs []string
			for k, v := range labels {
				pairs = append(pairs, `"`+k+`":"`+v+`"`)
			}
			_, _ = rec.WriteString(`{"Config":{"Labels":{` + strings.Join(pairs, ",") + `}}}`)
		}
	case req.Method == http.MethodDelete:
		if d.untagFail {
			rec.WriteHeader(http.StatusConflict)
			break
		}
		ref := strings.TrimPrefix(strings.TrimPrefix(req.URL.Path, "/libpod"), "/images/")
		d.untagged = append(d.untagged, req.URL.Path)
		delete(d.labels, ref)
		_, _ = rec.WriteString(`[{"Untagged":"` + ref + `"}]`)
	default:
		rec.WriteHeader(http.StatusNotFound)
	}
	return rec.Result(), nil
}

const pullProgress = `{"status":"Pulling from team/app"}` + "\n" + `{"status":"Status: Downloaded newer image for team/app:v2"}` + "\n"

func (d *pullMockDaemon) pull() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pulled = true
	if d.labels == nil {
		d.labels = map[string]map[string]string{}
	}
	for ref, labels := range d.written {
		d.labels[ref] = labels
	}
}

func runPull(t *testing.T, daemon *pullMockDaemon, target string, upstreamStatus int) (*httptest.ResponseRecorder, string) {
	t.Helper()
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	handler := MiddlewareWithRoundTripper(daemon, logger, Options{Owner: "job-123", LabelKey: "com.sockguard.owner"})(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			daemon.pull()
			w.WriteHeader(upstreamStatus)
			_, _ = io.WriteString(w, pullProgress)
		}))
	meta := &logging.RequestMeta{RolloutMode: "enforce"}
	req := httptest.NewRequest(http.MethodPost, target, nil)
	req = req.WithContext(logging.WithMeta(req.Context(), meta))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec, logs.String()
}

func TestPullUntagsAnImageWithAnotherOwnersLabel(t *testing.T) {
	t.Parallel()
	const key = "com.sockguard.owner"
	tests := []struct {
		name          string
		target        string
		ref           string
		labels        map[string]string
		inspectFail   bool
		untagFail     bool
		status        int
		wantUntagPath string
		wantErrorLine string
		wantErrorKey  string
	}{
		{
			name: "compat pull of a forged image", target: "/images/create?fromImage=team%2Fapp&tag=v2", ref: "team/app:v2",
			labels: map[string]string{key: "victim"}, status: http.StatusOK, wantUntagPath: "/images/team/app:v2",
			wantErrorLine: `"error":"owner policy removed pulled image team/app:v2: it carries another owner's label"`, wantErrorKey: `"errorDetail":{"message":`,
		},
		{
			name: "native pull of a forged image", target: "/v5.0.0/libpod/images/pull?reference=quay.io%2Fteam%2Fapp%3Av2", ref: "quay.io/team/app:v2",
			labels: map[string]string{key: "victim"}, status: http.StatusOK, wantUntagPath: "/libpod/images/quay.io/team/app:v2",
			wantErrorLine: `{"error":"owner policy removed pulled image quay.io/team/app:v2: it carries another owner's label"}`,
		},
		{name: "own label passes", target: "/images/create?fromImage=team%2Fapp&tag=v2", ref: "team/app:v2", labels: map[string]string{key: "job-123"}, status: http.StatusOK},
		{name: "no owner label passes", target: "/images/create?fromImage=team%2Fapp&tag=v2", ref: "team/app:v2", labels: map[string]string{"other": "x"}, status: http.StatusOK},
		{name: "empty owner label passes", target: "/images/create?fromImage=team%2Fapp&tag=v2", ref: "team/app:v2", labels: map[string]string{key: ""}, status: http.StatusOK},
		{name: "pull that wrote nothing passes", target: "/images/create?fromImage=team%2Fapp&tag=v2", ref: "team/app:v2", status: http.StatusOK},
		{name: "upstream refusal is not checked", target: "/images/create?fromImage=team%2Fapp&tag=v2", ref: "team/app:v2", labels: map[string]string{key: "victim"}, status: http.StatusNotFound},
		{
			name: "failed inspect fails closed", target: "/images/create?fromImage=team%2Fapp&tag=v2", ref: "team/app:v2",
			inspectFail: true, status: http.StatusOK, wantUntagPath: "/images/team/app:v2",
			wantErrorLine: `"error":"owner policy removed pulled image team/app:v2: its owner label could not be verified"`,
		},
		{
			name: "failed untag is reported", target: "/images/create?fromImage=team%2Fapp&tag=v2", ref: "team/app:v2",
			labels: map[string]string{key: "victim"}, untagFail: true, status: http.StatusOK,
			wantErrorLine: `"error":"owner policy could not remove pulled image team/app:v2`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			daemon := &pullMockDaemon{inspectFail: map[string]bool{tt.ref: tt.inspectFail}, untagFail: tt.untagFail}
			if tt.labels != nil {
				daemon.written = map[string]map[string]string{tt.ref: tt.labels}
			}
			rec, logs := runPull(t, daemon, tt.target, tt.status)

			body := rec.Body.String()
			if !strings.HasPrefix(body, pullProgress) {
				t.Fatalf("stream does not begin with the daemon's progress: %q", body)
			}
			tail := strings.TrimPrefix(body, pullProgress)
			if tt.wantErrorLine == "" {
				if tail != "" || len(daemon.untagged) != 0 {
					t.Fatalf("tail = %q, untagged = %v, want a stream left untouched", tail, daemon.untagged)
				}
				return
			}
			if !strings.HasSuffix(tail, "\n") || strings.Count(tail, "\n") != 1 || !strings.Contains(tail, tt.wantErrorLine) {
				t.Fatalf("tail = %q, want one line containing %s", tail, tt.wantErrorLine)
			}
			if tt.wantErrorKey != "" && !strings.Contains(tail, tt.wantErrorKey) {
				t.Fatalf("tail = %q, want %s", tail, tt.wantErrorKey)
			}
			if tt.wantUntagPath != "" && (len(daemon.untagged) != 1 || daemon.untagged[0] != tt.wantUntagPath) {
				t.Fatalf("untagged = %v, want [%s]", daemon.untagged, tt.wantUntagPath)
			}
			if tt.untagFail && !strings.Contains(logs, "level=ERROR") {
				t.Fatalf("logs = %q, want an error record for the failed untag", logs)
			}
			if !tt.untagFail && !strings.Contains(logs, "level=WARN") {
				t.Fatalf("logs = %q, want a warn record", logs)
			}
		})
	}
}

// A short name on a Podman-shaped destination is checked under both names, and
// each one the pull wrote is dealt with.
func TestPullChecksBothNamesOfAShortNameOnPodman(t *testing.T) {
	t.Parallel()
	daemon := &pullMockDaemon{written: map[string]map[string]string{
		"localhost/team/app:v2": {"com.sockguard.owner": "victim"},
	}}
	var logs bytes.Buffer
	handler := MiddlewareWithRoundTripper(daemon, slog.New(slog.NewTextHandler(&logs, nil)), Options{Owner: "job-123", LabelKey: "com.sockguard.owner"})(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { daemon.pull(); _, _ = io.WriteString(w, pullProgress) }))
	req := httptest.NewRequest(http.MethodPost, "/v5.0.0/libpod/images/pull?reference=team%2Fapp%3Av2", nil)
	req = req.WithContext(logging.WithMeta(req.Context(), &logging.RequestMeta{RolloutMode: "enforce"}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if len(daemon.untagged) != 1 || daemon.untagged[0] != "/libpod/images/localhost/team/app:v2" {
		t.Fatalf("untagged = %v", daemon.untagged)
	}
	if !strings.Contains(rec.Body.String(), "owner policy removed pulled image localhost/team/app:v2") {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

// Warn and audit rollouts forward what enforce would refuse, so they leave the
// pulled image alone.
func TestPullCheckSkippedInWarnRollout(t *testing.T) {
	t.Parallel()
	daemon := &pullMockDaemon{written: map[string]map[string]string{"team/app:v2": {"com.sockguard.owner": "victim"}}}
	handler := MiddlewareWithRoundTripper(daemon, slog.New(slog.NewTextHandler(io.Discard, nil)), Options{Owner: "job-123", LabelKey: "com.sockguard.owner"})(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { daemon.pull(); _, _ = io.WriteString(w, pullProgress) }))
	req := httptest.NewRequest(http.MethodPost, "/images/create?fromImage=team%2Fapp&tag=v2", nil)
	req = req.WithContext(logging.WithMeta(req.Context(), &logging.RequestMeta{RolloutMode: "warn"}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Body.String() != pullProgress || len(daemon.untagged) != 0 {
		t.Fatalf("body = %q untagged = %v, want the stream untouched", rec.Body.String(), daemon.untagged)
	}
}

func TestImagePullProgressErrorShapes(t *testing.T) {
	t.Parallel()
	if got := imagePullProgressError(true, `a "b"`); got != `{"error":"a \"b\""}` {
		t.Fatalf("libpod = %s", got)
	}
	if got := imagePullProgressError(false, "m"); got != `{"errorDetail":{"message":"m"},"error":"m"}` {
		t.Fatalf("compat = %s", got)
	}
}
