package filter

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/logging"
)

func TestExecTargetPinsInspectedIdentity(t *testing.T) {
	id := strings.Repeat("a", 64)
	for _, route := range []struct{ input, want string }{
		{"/containers/alias/exec", "/containers/" + id + "/exec"},
		{"/v1.45/containers/alias/exec", "/v1.45/containers/" + id + "/exec"},
		{"/v5.0.0/libpod/containers/alias/exec", "/v5.0.0/libpod/containers/" + id + "/exec"},
		{"/containers/x/../alias/exec", "/containers/" + id + "/exec"},
	} {
		t.Run(route.input, func(t *testing.T) {
			rt := execRoundTripperFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path != "/containers/alias/json" {
					t.Fatalf("inspect path = %q", r.URL.Path)
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"Id":"` + id + `","Config":{"Labels":{}}}`))}, nil
			})
			policy := newExecPolicy(ExecOptions{AllowRootUser: true, AllowBlindWrites: true, InspectTarget: NewExecTargetInspectorWithRoundTripper(rt)})
			r := httptest.NewRequest(http.MethodPost, route.input, strings.NewReader(`{"Cmd":["/bin/sh"]}`))
			meta := &logging.RequestMeta{NormPath: NormalizePath(r.URL.Path)}
			r = r.WithContext(logging.WithMeta(r.Context(), meta))
			if reason, err := policy.inspect(testLogger(), r, NormalizePath(r.URL.Path)); err != nil || reason != "" {
				t.Fatalf("inspect = %q, %v", reason, err)
			}
			if r.URL.Path != route.want || r.URL.RawPath != "" {
				t.Fatalf("forward path = %q (raw %q), want %q", r.URL.Path, r.URL.RawPath, route.want)
			}
			if meta.NormPath != NormalizePath(route.want) {
				t.Fatalf("downstream policy path = %q, want pinned identity", meta.NormPath)
			}
		})
	}
}

func TestExecTargetInspectorFailures(t *testing.T) {
	id := strings.Repeat("a", 64)
	for _, tc := range []struct {
		name      string
		status    int
		body      string
		protected bool
		found     bool
		wantErr   bool
	}{
		{"protected", 200, `{"Id":"` + id + `","Config":{"Labels":{"com.sockguard.exec":"deny"}}}`, true, true, false},
		{"ordinary", 200, `{"Id":"` + id + `","Config":{"Labels":null}}`, false, true, false},
		{"missing", 404, `{}`, false, false, false},
		{"upstream failure", 500, `{}`, false, false, true},
		{"invalid JSON", 200, `{`, false, false, true},
		{"missing config", 200, `{"Id":"` + id + `"}`, false, false, true},
		{"invalid labels", 200, `{"Config":{"Labels":[]}}`, false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inspect := NewExecTargetInspectorWithRoundTripper(execRoundTripperFunc(func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodGet || r.URL.Path != "/containers/"+id+"/json" {
					t.Fatalf("unexpected inspect %s %s", r.Method, r.URL.Path)
				}
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			}))
			got, found, err := inspect(context.Background(), id)
			if (err != nil) != tc.wantErr || found != tc.found || got.Protected != tc.protected {
				t.Fatalf("inspect = %+v, %v, %v", got, found, err)
			}
		})
	}
	t.Run("transport failure", func(t *testing.T) {
		sentinel := errors.New("engine unavailable")
		inspect := NewExecTargetInspectorWithRoundTripper(execRoundTripperFunc(func(*http.Request) (*http.Response, error) { return nil, sentinel }))
		if _, _, err := inspect(context.Background(), id); !errors.Is(err, sentinel) {
			t.Fatalf("error = %v, want transport failure", err)
		}
	})
}
