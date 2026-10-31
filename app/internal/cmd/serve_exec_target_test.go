package cmd

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/config"
)

func TestServeDeniesExecIntoProtectedContainer(t *testing.T) {
	for _, path := range []string{
		"/containers/proxy/exec",
		"/exec/session/start",
		"/libpod/containers/proxy/exec",
		"/libpod/exec/session/start",
	} {
		t.Run(path, func(t *testing.T) {
			socketPath := shortSocketPath(t, "exec-target")
			var writes atomic.Int32
			startUnixHTTPUpstream(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/exec/"):
					_, _ = io.WriteString(w, `{"ContainerID":"proxy","ProcessConfig":{"entrypoint":"/bin/sh","user":"root"}}`)
				case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/containers/"):
					_, _ = io.WriteString(w, `{"Id":"proxy","Config":{"Labels":{"com.sockguard.exec":"deny"}}}`)
				case r.Method == http.MethodPost:
					writes.Add(1)
					w.WriteHeader(http.StatusNoContent)
				default:
					http.NotFound(w, r)
				}
			}))
			cfg := config.Defaults()
			cfg.Upstream.Socket = socketPath
			cfg.Health.Enabled = false
			cfg.Log.AccessLog = false
			cfg.InsecureAllowBodyBlindWrites = true
			cfg.RequestBody.Exec.AllowRootUser = true
			cfg.Rules = []config.RuleConfig{{Match: config.MatchConfig{Method: http.MethodPost, Path: "/**"}, Action: "allow"}}
			rules, err := compileRuleConfigsForTest(cfg.Rules)
			if err != nil {
				t.Fatal(err)
			}
			handler := buildServeHandler(t, &cfg, newDiscardLogger(), nil, rules, newServeTestDeps())
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"Cmd":["/bin/sh"]}`)))
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body: %s", rec.Code, rec.Body.String())
			}
			if got := writes.Load(); got != 0 {
				t.Fatalf("upstream writes = %d, want 0", got)
			}
		})
	}
}
