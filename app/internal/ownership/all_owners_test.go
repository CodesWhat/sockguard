package ownership

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/dockerresource"
)

func TestAllOwnersStampsCreatesAndChecksNothing(t *testing.T) {
	t.Parallel()

	failInspect := func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error) {
		t.Error("scope all must not inspect a resource for an owner check")
		return nil, false, nil
	}
	failExec := func(context.Context, string) (string, bool, error) {
		t.Error("scope all must not inspect an exec for an owner check")
		return "", false, nil
	}

	tests := []struct {
		name, method, path, body string
		wantStatus               int
		check                    func(t *testing.T, got *http.Request, body string)
	}{
		{"container create is stamped", http.MethodPost, "/containers/create", `{"Image":"alpine"}`, http.StatusNoContent,
			func(t *testing.T, _ *http.Request, body string) {
				if !strings.Contains(body, `"com.sockguard.owner":"adm"`) {
					t.Errorf("create body = %s, want the owner label stamped", body)
				}
			}},
		{"list is not narrowed", http.MethodGet, "/containers/json", "", http.StatusNoContent,
			func(t *testing.T, got *http.Request, _ string) {
				if f := got.URL.Query().Get("filters"); f != "" {
					t.Errorf("filters = %q, want none injected", f)
				}
			}},
		{"foreign container delete is not checked", http.MethodDelete, "/containers/victim", "", http.StatusNoContent, nil},
		{"unscopeable libpod read is not refused", http.MethodGet, "/libpod/generate/kube", "", http.StatusNoContent, nil},
		{"docker build stays refused", http.MethodPost, "/build", "", http.StatusForbidden, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotReq *http.Request
			var gotBody string
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotReq = r
				b, _ := io.ReadAll(r.Body)
				gotBody = string(b)
				w.WriteHeader(http.StatusNoContent)
			})
			handler := middlewareWithDeps(testLogger(), Options{Owner: "adm", LabelKey: "com.sockguard.owner", AllOwners: true},
				failInspect, failExec)(next)
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if tt.check != nil && gotReq != nil {
				tt.check(t, gotReq, gotBody)
			}
		})
	}
}

type failTransport struct{ t *testing.T }

func (f failTransport) RoundTrip(*http.Request) (*http.Response, error) {
	f.t.Error("authorizer must not contact the daemon under scope all")
	return nil, io.ErrUnexpectedEOF
}

func TestAllOwnersBuildkitImageAuthorizerAllowsAnyDestination(t *testing.T) {
	t.Parallel()
	authorize := NewBuildkitImageAuthorizer(failTransport{t}, Options{Owner: "adm", AllOwners: true})
	if err := authorize(context.Background(), "registry.example/other-owner/app:1"); err != nil {
		t.Fatalf("authorize = %v, want nil under scope all", err)
	}
}
