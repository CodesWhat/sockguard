package filter

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/logging"
)

func TestLibpodCreateHostsFileSelectors(t *testing.T) {
	container := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{})
	wide := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowedBindMounts: []string{"/"}})
	pod := newLibpodPodCreatePolicy(LibpodPodCreateOptions{})
	targets := []struct {
		name      string
		operation string
		field     string
		base      string
		malformed string
		inspect   func(*testing.T, []byte) string
	}{
		{"container", "libpod container create", "base_hosts_file", `"systemd":"false"`, "libpod container create denied: malformed JSON request body", func(t *testing.T, body []byte) string { return inspectLibpod(t, container, body) }},
		{"container with root bind allowlisted", "libpod container create", "base_hosts_file", `"systemd":"false"`, "libpod container create denied: malformed JSON request body", func(t *testing.T, body []byte) string { return inspectLibpod(t, wide, body) }},
		{"pod", "libpod pod create", "hostsFile", `"name":"my-pod"`, "libpod pod create denied: request body could not be inspected", func(t *testing.T, body []byte) string { return inspectLibpodPod(t, pod, body) }},
	}
	cases := []struct {
		name      string
		value     string
		deny      bool
		malformed bool
	}{
		{name: "empty", value: `""`},
		{name: "image", value: `"image"`},
		{name: "none", value: `"none"`},
		{name: "null", value: `null`},
		{name: "absolute host path", value: `"/host/hosts"`, deny: true},
		{name: "explicit default path", value: `"/etc/hosts"`, deny: true},
		{name: "relative host path", value: `"hosts"`, deny: true},
		{name: "parent path", value: `"../hosts"`, deny: true},
		{name: "whitespace path", value: `" "`, deny: true},
		{name: "upper case selector", value: `"IMAGE"`, deny: true},
		{name: "padded selector", value: `" none "`, deny: true},
		{name: "selector prefix", value: `"image/hosts"`, deny: true},
		{name: "object", value: `{"path":"/host/hosts"}`, malformed: true},
		{name: "array", value: `["/host/hosts"]`, malformed: true},
		{name: "number", value: `1`, malformed: true},
	}
	for _, target := range targets {
		for _, field := range []string{target.field, strings.ToUpper(target.field)} {
			for _, tc := range cases {
				t.Run(target.name+"/"+field+"/"+tc.name, func(t *testing.T) {
					body := []byte(fmt.Sprintf(`{%s,%q:%s}`, target.base, field, tc.value))
					want := ""
					if tc.deny {
						want = fmt.Sprintf("%s denied: setting %s to a host path is not allowed", target.operation, target.field)
					}
					if tc.malformed {
						want = target.malformed
					}
					if got := target.inspect(t, body); got != want {
						t.Fatalf("reason = %q, want %q", got, want)
					}
				})
			}
		}
	}
}

func TestLibpodCreateHostsFileMiddleware(t *testing.T) {
	targets := []struct{ path, field, base string }{
		{"/libpod/containers/create", "base_hosts_file", `"systemd":"false"`},
		{"/libpod/pods/create", "hostsFile", `"name":"my-pod"`},
	}
	for _, target := range targets {
		rule, err := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: target.path, Action: ActionAllow})
		if err != nil {
			t.Fatal(err)
		}
		for _, prefix := range []string{"", "/v6.1.3"} {
			for _, mode := range []string{"enforce", "warn", "audit"} {
				for _, value := range []string{"/host/hosts", "image", "none", ""} {
					t.Run(target.path+"/"+prefix+"/"+mode+"/"+value, func(t *testing.T) {
						body := fmt.Sprintf(`{%s,%q:%q}`, target.base, target.field, value)
						forwarded := false
						handler := MiddlewareWithOptions([]*CompiledRule{rule}, testLogger(), Options{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							forwarded = true
							got, err := io.ReadAll(r.Body)
							if err != nil {
								t.Fatal(err)
							}
							if string(got) != body {
								t.Fatalf("forwarded body = %q, want %q", got, body)
							}
							w.WriteHeader(http.StatusCreated)
						}))
						meta := &logging.RequestMeta{RolloutMode: mode}
						req := httptest.NewRequest(http.MethodPost, prefix+target.path, strings.NewReader(body))
						req = req.WithContext(logging.WithMeta(req.Context(), meta))
						rec := httptest.NewRecorder()
						handler.ServeHTTP(rec, req)
						wantStatus := http.StatusCreated
						if value == "/host/hosts" {
							if mode == "enforce" {
								wantStatus = http.StatusForbidden
							} else if meta.Decision != logging.DecisionWouldDeny {
								t.Fatalf("decision = %q, want %q", meta.Decision, logging.DecisionWouldDeny)
							}
						}
						if rec.Code != wantStatus {
							t.Fatalf("status = %d, want %d: %s", rec.Code, wantStatus, rec.Body.String())
						}
						if forwarded != (wantStatus == http.StatusCreated) {
							t.Fatalf("forwarded = %t, want %t", forwarded, wantStatus == http.StatusCreated)
						}
					})
				}
			}
		}
	}
}
