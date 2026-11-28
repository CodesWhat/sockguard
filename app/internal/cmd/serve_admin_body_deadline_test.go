package cmd

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v3/app/internal/admin"
	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

func TestSharedAdminBodyDeadline(t *testing.T) {
	cfg := config.Defaults()
	cfg.Admin.Enabled = true
	cfg.Admin.MaxRequestBytes = 128
	logger, deps := newDiscardLogger(), newServeTestDeps()
	runtime, err := newServeRuntime(&cfg, logger, deps)
	if err != nil {
		t.Fatal(err)
	}
	rules := adminTestRules(t)
	versioner := admin.NewPolicyVersioner()
	versioner.Update(buildInitialPolicySnapshot(deps, &cfg, rules, false, nil))
	h, stop, _ := buildServeHandlerChainWithRuntime(serveHandlerBuild{
		Cfg: &cfg, Logger: logger, Rules: rules, Deps: deps, Runtime: runtime, Versioner: versioner,
	})
	t.Cleanup(stop)

	const candidate = "rules:\n  - match: {method: GET, path: /_ping}\n    action: allow\n"
	for _, path := range []string{cfg.Admin.Path, cfg.Admin.PolicyDiffPath} {
		t.Run(path, func(t *testing.T) {
			for _, tc := range []struct {
				name   string
				input  string
				err    error
				status int
			}{
				{name: "valid", input: candidate, status: http.StatusOK},
				{name: "timed out", err: os.ErrDeadlineExceeded, status: http.StatusRequestTimeout},
				{name: "too large", input: strings.Repeat("a", 129), status: http.StatusRequestEntityTooLarge},
			} {
				t.Run(tc.name, func(t *testing.T) {
					w := &adminDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
					body := &adminDeadlineBody{reader: strings.NewReader(tc.input), err: tc.err, writer: w}
					start := time.Now()
					h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, body))

					if w.Code != tc.status {
						t.Errorf("status = %d, want %d; body = %s", w.Code, tc.status, w.Body)
					}
					if len(w.calls) != 2 {
						t.Fatalf("deadline calls = %v, want set followed by clear", w.calls)
					}
					if deadline := w.calls[0]; deadline.Before(start.Add(30*time.Second)) || deadline.After(time.Now().Add(30*time.Second)) {
						t.Errorf("read deadline = %s, want a deadline 30 seconds after the request begins", deadline)
					}
					if !body.readDeadline.Equal(w.calls[0]) || !body.closeDeadline.Equal(w.calls[0]) {
						t.Errorf("body deadlines = read %s and close %s, want %s for both", body.readDeadline, body.closeDeadline, w.calls[0])
					}
					if !w.calls[1].IsZero() || !w.responseDeadline.IsZero() {
						t.Errorf("deadline was not cleared before response: %s", w.responseDeadline)
					}
				})
			}
		})
	}
}

func TestAdminBodyDeadlineLeavesOtherHandlersUnscoped(t *testing.T) {
	cfg := config.Defaults()
	cfg.Admin.Enabled = true
	logger, deps := newDiscardLogger(), newServeTestDeps()
	runtime, err := newServeRuntime(&cfg, logger, deps)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodGet, Path: "/events"}, Action: "allow"},
	}
	rules, err := validateAndCompileRules(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	layers, stop, _ := buildServeHandlerLayersWithRuntime(serveHandlerBuild{
		Cfg: &cfg, Logger: logger, Rules: rules, Deps: deps, Runtime: runtime,
	})
	t.Cleanup(stop)
	stream := &adminDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	var streamDeadline time.Time
	var h http.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		streamDeadline = stream.deadline
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "event\n")
		_ = http.NewResponseController(w).Flush()
	})
	for _, layer := range layers {
		h = layer.with(h)
	}

	h.ServeHTTP(stream, httptest.NewRequest(http.MethodGet, "/events", nil))
	if stream.Code != http.StatusOK || !stream.Flushed || !streamDeadline.IsZero() || !stream.responseDeadline.IsZero() {
		t.Fatalf("stream status = %d, flushed = %v, response deadline = %s", stream.Code, stream.Flushed, stream.responseDeadline)
	}
	if newHTTPServer(h).ReadTimeout != 0 {
		t.Fatal("shared server has a connection-wide read timeout")
	}

	cfg.Admin.Listen.Address = "127.0.0.1:0"
	versioner := admin.NewPolicyVersioner()
	versioner.Update(buildInitialPolicySnapshot(deps, &cfg, rules, false, nil))
	dedicated := buildAdminHandlerChain(&cfg, logger, nil, versioner, nil)
	for _, path := range []string{cfg.Admin.Path, cfg.Admin.PolicyDiffPath} {
		deadline := time.Now().Add(time.Minute)
		w := &adminDeadlineRecorder{ResponseRecorder: httptest.NewRecorder(), deadline: deadline}
		dedicated.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, strings.NewReader("rules: []")))
		if w.Code != http.StatusOK || len(w.calls) != 0 || !w.responseDeadline.Equal(deadline) {
			t.Fatalf("dedicated %s status = %d, deadline calls = %v, response deadline = %s", path, w.Code, w.calls, w.responseDeadline)
		}
	}
}

type adminDeadlineRecorder struct {
	*httptest.ResponseRecorder
	calls            []time.Time
	deadline         time.Time
	responseDeadline time.Time
}

func (w *adminDeadlineRecorder) SetReadDeadline(deadline time.Time) error {
	w.deadline = deadline
	w.calls = append(w.calls, deadline)
	return nil
}

func (w *adminDeadlineRecorder) WriteHeader(statusCode int) {
	w.responseDeadline = w.deadline
	w.ResponseRecorder.WriteHeader(statusCode)
}

type adminDeadlineBody struct {
	reader        io.Reader
	err           error
	writer        *adminDeadlineRecorder
	readDeadline  time.Time
	closeDeadline time.Time
}

func (b *adminDeadlineBody) Read(p []byte) (int, error) {
	b.readDeadline = b.writer.deadline
	if b.err != nil {
		return 0, b.err
	}
	return b.reader.Read(p)
}

func (b *adminDeadlineBody) Close() error {
	b.closeDeadline = b.writer.deadline
	return nil
}
