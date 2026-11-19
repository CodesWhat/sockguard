package ownership

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/dockerresource"
)

func TestNetworkIdentifierAuthorizesTheWholeSlashBearingName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		method, path, want string
		ok                 bool
	}{
		{http.MethodPost, "/networks/web/connect", "web", true},
		{http.MethodPost, "/networks/a/b/connect", "a/b", true},
		{http.MethodPost, "/networks/a/b/c/disconnect", "a/b/c", true},
		{http.MethodDelete, "/networks/a/b", "a/b", true},
		{http.MethodGet, "/networks/a/b", "a/b", true},
		{http.MethodDelete, "/networks/web", "web", true},
		{http.MethodPost, "/networks/create", "", false},
		{http.MethodPost, "/networks/prune", "", false},
		{http.MethodPost, "/networks/a/b/other", "a/b/other", true},
	}
	for _, tt := range tests {
		got, ok := networkIdentifier(tt.method, tt.path)
		if got != tt.want || ok != tt.ok {
			t.Errorf("networkIdentifier(%s, %q) = (%q, %v), want (%q, %v)", tt.method, tt.path, got, ok, tt.want, tt.ok)
		}
	}
	for path, want := range map[string]bool{
		"/networks/a/b/connect":           true,
		"/networks/a/b/disconnect":        true,
		"/networks/connect":               false,
		"/networks//connect":              false,
		"/libpod/networks/a/connect":      true,
		"/libpod/networks/a/b/connect":    false,
		"/libpod/networks/a/b/disconnect": false,
		"/networks/a/b/connectx":          false,
	} {
		if got := isNetworkMembershipChangePath(path); got != want {
			t.Errorf("isNetworkMembershipChangePath(%q) = %v, want %v", path, got, want)
		}
	}
}

// TestMiddlewareChecksTheFullNetworkNameAndBodyContainer pins the fix for a
// slash-bearing network name: dockerd routes /networks/{id:.*}/connect, so
// POST /networks/a/b/connect acts on network "a/b". Ownership used to check
// only "a" and never collected the body's Container.
func TestMiddlewareChecksTheFullNetworkNameAndBodyContainer(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	requests := []struct {
		method, target, body string
		container            bool
	}{
		{http.MethodPost, "/networks/a/b/connect", `{"Container":"victim"}`, true},
		{http.MethodPost, "/v1.45/networks/a/b/disconnect", `{"Container":"victim"}`, true},
		{http.MethodPost, "/networks/a%2Fb/connect", `{"Container":"victim"}`, true},
		{http.MethodDelete, "/networks/a/b", ``, false},
		{http.MethodGet, "/networks/a/b", ``, false},
	}
	for _, req := range requests {
		for _, tc := range []struct {
			name         string
			network, ctr string
			wantCode     int
			forwarded    bool
		}{
			{"both owned", "job-123", "job-123", http.StatusOK, true},
			{"foreign network", "job-999", "job-123", http.StatusForbidden, false},
			{"foreign container", "job-123", "job-999", http.StatusForbidden, false},
		} {
			if !req.container && tc.name == "foreign container" {
				continue
			}
			t.Run(req.method+" "+req.target+" "+tc.name, func(t *testing.T) {
				t.Parallel()
				fi := &recordingInspector{resources: map[string]map[string]inspectResult{
					string(dockerresource.KindNetwork):   {"a/b": ownerLabel(tc.network), "a": ownerLabel("job-123")},
					string(dockerresource.KindContainer): {"victim": ownerLabel(tc.ctr)},
				}}
				forwarded := false
				handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					forwarded = true
				}))
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httptest.NewRequest(req.method, req.target, strings.NewReader(req.body)))
				if rec.Code != tc.wantCode || forwarded != tc.forwarded {
					t.Fatalf("status = %d forwarded = %v, want %d / %v", rec.Code, forwarded, tc.wantCode, tc.forwarded)
				}
				var sawNetwork, sawContainer bool
				for _, call := range fi.calls {
					switch {
					case call.kind == dockerresource.KindNetwork && call.id == "a/b":
						sawNetwork = true
					case call.kind == dockerresource.KindNetwork:
						t.Errorf("inspected truncated network %q", call.id)
					case call.kind == dockerresource.KindContainer && call.id == "victim":
						sawContainer = true
					}
				}
				if !sawNetwork && tc.name != "foreign container" {
					t.Errorf("network a/b was not inspected: %#v", fi.calls)
				}
				if req.container && tc.wantCode == http.StatusOK && !sawContainer {
					t.Errorf("body container was not inspected: %#v", fi.calls)
				}
			})
		}
	}
}
