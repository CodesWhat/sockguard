package filter

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/logging"
)

// TestLogPathRefusalFollowsRolloutMode pins that a client-supplied log path
// is denied in enforce mode and only recorded as would-deny (body forwarded
// unchanged) in warn and audit, on both the compat and native libpod create
// routes, and that allow_log_path passes it in every mode.
func TestLogPathRefusalFollowsRolloutMode(t *testing.T) {
	routes := []struct {
		name       string
		path       string
		body       string
		wantReason string
		options    func(allow bool) Options
	}{
		{
			name:       "compat",
			path:       "/containers/create",
			body:       `{"Image":"alpine","HostConfig":{"LogConfig":{"Type":"k8s-file","Config":{"path":"/host/x.log"}}}}`,
			wantReason: "container create denied: setting a log path in HostConfig.LogConfig.Config is not allowed (set allow_log_path: true)",
			options: func(allow bool) Options {
				return Options{ContainerCreate: ContainerCreateOptions{AllowLogPath: allow}}
			},
		},
		{
			name:       "libpod",
			path:       "/libpod/containers/create",
			body:       `{"image":"alpine","systemd":"false","log_configuration":{"driver":"k8s-file","path":"/host/x.log"}}`,
			wantReason: "libpod container create denied: setting log_configuration.path is not allowed (set allow_log_path: true)",
			options: func(allow bool) Options {
				return Options{LibpodContainerCreate: LibpodContainerCreateOptions{AllowLogPath: allow}}
			},
		},
	}

	for _, route := range routes {
		rule, err := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: route.path, Action: ActionAllow})
		if err != nil {
			t.Fatal(err)
		}
		for _, mode := range []string{"enforce", "warn", "audit"} {
			for _, allow := range []bool{false, true} {
				name := route.name + "/" + mode + "/allow_log_path=off"
				if allow {
					name = route.name + "/" + mode + "/allow_log_path=on"
				}
				t.Run(name, func(t *testing.T) {
					forwarded := false
					handler := MiddlewareWithOptions([]*CompiledRule{rule}, testLogger(), route.options(allow))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						forwarded = true
						got, err := io.ReadAll(r.Body)
						if err != nil {
							t.Fatal(err)
						}
						if string(got) != route.body {
							t.Fatalf("forwarded body = %q, want %q", got, route.body)
						}
						w.WriteHeader(http.StatusCreated)
					}))
					meta := &logging.RequestMeta{RolloutMode: mode}
					req := httptest.NewRequest(http.MethodPost, route.path, strings.NewReader(route.body))
					req = req.WithContext(logging.WithMeta(req.Context(), meta))
					rec := httptest.NewRecorder()
					handler.ServeHTTP(rec, req)

					denied := !allow && mode == "enforce"
					wantStatus := http.StatusCreated
					if denied {
						wantStatus = http.StatusForbidden
					}
					if rec.Code != wantStatus {
						t.Fatalf("status = %d, want %d: %s", rec.Code, wantStatus, rec.Body.String())
					}
					if forwarded == denied {
						t.Fatalf("forwarded = %t, want %t", forwarded, !denied)
					}
					switch {
					case denied:
						if meta.Reason != route.wantReason {
							t.Fatalf("reason = %q, want %q", meta.Reason, route.wantReason)
						}
					case !allow:
						if meta.Decision != logging.DecisionWouldDeny {
							t.Fatalf("decision = %q, want %q", meta.Decision, logging.DecisionWouldDeny)
						}
					default:
						if meta.Decision == logging.DecisionWouldDeny {
							t.Fatalf("decision = %q (reason %q) with allow_log_path on", meta.Decision, meta.Reason)
						}
					}
				})
			}
		}
	}
}
