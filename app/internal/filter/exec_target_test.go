package filter

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/logging"
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

func TestExecTargetDenyReason(t *testing.T) {
	goodID := strings.Repeat("a", 64)
	errBoom := errors.New("boom")

	tests := []struct {
		name         string
		id           string
		result       ExecTargetInspectResult
		found        bool
		inspectErr   error
		nilInspector bool
		wantID       string
		wantReason   string
		wantErr      error
		wantStatus   int
		wantCalls    int
	}{
		{name: "ok target returns inspected id", id: "web", result: ExecTargetInspectResult{ContainerID: goodID}, found: true, wantID: goodID, wantCalls: 1},
		{name: "protected target denied", id: "web", result: ExecTargetInspectResult{ContainerID: goodID, Protected: true}, found: true, wantReason: "exec denied: target container is protected by com.sockguard.exec=deny", wantCalls: 1},
		{name: "short id denied", id: "web", result: ExecTargetInspectResult{ContainerID: "abc123"}, found: true, wantReason: "exec denied: target container identity could not be inspected", wantCalls: 1},
		{name: "non-hex 64 char id denied", id: "web", result: ExecTargetInspectResult{ContainerID: strings.Repeat("z", 64)}, found: true, wantReason: "exec denied: target container identity could not be inspected", wantCalls: 1},
		{name: "not found rejected with 404", id: "web", found: false, wantStatus: http.StatusNotFound, wantCalls: 1},
		{name: "inspector error propagates", id: "web", inspectErr: errBoom, wantErr: errBoom, wantCalls: 1},
		{name: "empty id denied without inspecting", id: "", wantReason: "exec denied: target container could not be resolved"},
		{name: "nil inspector allows", id: "web", nilInspector: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			opts := ExecOptions{AllowRootUser: true, AllowBlindWrites: true}
			if !tc.nilInspector {
				opts.InspectTarget = func(_ context.Context, id string) (ExecTargetInspectResult, bool, error) {
					calls++
					if id != tc.id {
						t.Fatalf("inspector id = %q, want %q", id, tc.id)
					}
					return tc.result, tc.found, tc.inspectErr
				}
			}
			policy := newExecPolicy(opts)

			gotID, reason, err := policy.targetDenyReason(context.Background(), tc.id)

			if calls != tc.wantCalls {
				t.Fatalf("inspector calls = %d, want %d", calls, tc.wantCalls)
			}
			switch {
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want wrapping %v", err, tc.wantErr)
				}
			case tc.wantStatus != 0:
				rej, ok := requestRejectionFromError(err)
				if !ok || rej.status != tc.wantStatus {
					t.Fatalf("err = %v, want rejection with status %d", err, tc.wantStatus)
				}
			default:
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
			}
			if gotID != tc.wantID {
				t.Fatalf("id = %q, want %q", gotID, tc.wantID)
			}
			if reason != tc.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tc.wantReason)
			}
		})
	}
}
