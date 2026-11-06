package ownership

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/dockerresource"
	"github.com/codeswhat/sockguard/v3/app/internal/logging"
	"github.com/codeswhat/sockguard/v3/app/internal/upstreamflavor"
)

func TestPodmanNetworkDeleteRequiresCanonicalName(t *testing.T) {
	t.Parallel()
	id := strings.Repeat("a", 64)
	tests := []struct {
		name, method, path, body string
		want                     int
		memo                     bool
		docker                   bool
	}{
		{name: "malformed inspect", method: http.MethodDelete, path: "/libpod/networks/mine", body: `{`, want: http.StatusBadGateway},
		{name: "oversized inspect", method: http.MethodDelete, path: "/libpod/networks/mine", body: strings.Repeat(" ", 1<<20) + `{}`, want: http.StatusBadGateway},
		{name: "owned name", method: http.MethodDelete, path: "/libpod/networks/mine", body: `{"Name":"mine","Labels":{"com.sockguard.owner":"job-123"}}`, want: http.StatusNoContent},
		{name: "owned ID", method: http.MethodDelete, path: "/libpod/networks/" + id, body: `{"Name":"mine","Labels":{"com.sockguard.owner":"job-123"}}`, want: http.StatusNotFound},
		{name: "owned ID prefix", method: http.MethodDelete, path: "/libpod/networks/aaaa", body: `{"Name":"mine","Labels":{"com.sockguard.owner":"job-123"}}`, want: http.StatusNotFound},
		{name: "ID with visibility memo", method: http.MethodDelete, path: "/libpod/networks/" + id, body: `{"Name":"mine","Labels":{"com.sockguard.owner":"job-123"}}`, want: http.StatusNotFound, memo: true},
		{name: "foreign name", method: http.MethodDelete, path: "/libpod/networks/mine", body: `{"Name":"mine","Labels":{"com.sockguard.owner":"other"}}`, want: http.StatusForbidden},
		{name: "missing canonical name", method: http.MethodDelete, path: "/libpod/networks/" + id, body: `{"Labels":{"com.sockguard.owner":"job-123"}}`, want: http.StatusNotFound},
		{name: "compat Podman ID", method: http.MethodDelete, path: "/networks/" + id, body: `{"Name":"mine","Labels":{"com.sockguard.owner":"job-123"}}`, want: http.StatusNotFound},
		{name: "compat Podman name", method: http.MethodDelete, path: "/networks/mine", body: `{"Name":"mine","Labels":{"com.sockguard.owner":"job-123"}}`, want: http.StatusNoContent},
		{name: "compat Podman prefix", method: http.MethodDelete, path: "/networks/aaaa", body: `{"Name":"mine","Labels":{"com.sockguard.owner":"job-123"}}`, want: http.StatusNotFound},
		{name: "compat Podman ID with visibility memo", method: http.MethodDelete, path: "/networks/" + id, body: `{"Name":"mine","Labels":{"com.sockguard.owner":"job-123"}}`, want: http.StatusNotFound, memo: true},
		{name: "compat Docker ID", method: http.MethodDelete, path: "/networks/" + id, body: `{"Name":"mine","Labels":{"com.sockguard.owner":"job-123"}}`, want: http.StatusNoContent, docker: true},
		{name: "native inspect by ID unchanged", method: http.MethodGet, path: "/libpod/networks/" + id + "/json", body: `{"Name":"mine","Labels":{"com.sockguard.owner":"job-123"}}`, want: http.StatusNoContent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := buildImageTransport(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(tt.body)), Request: r}, nil
			})
			forwarded := false
			flavor := upstreamflavor.Podman
			if tt.docker {
				flavor = upstreamflavor.Docker
			}
			handler := MiddlewareWithRoundTripper(rt, testLogger(), Options{Owner: "job-123", LabelKey: "com.sockguard.owner", UpstreamFlavor: flavor})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded = true; w.WriteHeader(http.StatusNoContent) }))
			req := httptest.NewRequest(tt.method, tt.path, nil)
			meta := &logging.RequestMeta{}
			if tt.memo {
				meta.RecordInspectedLabels(string(dockerresource.KindNetwork), id, map[string]string{"com.sockguard.owner": "job-123"}, true)
			}
			req = req.WithContext(logging.WithMeta(req.Context(), meta))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tt.want || forwarded != (tt.want == http.StatusNoContent) {
				t.Fatalf("status=%d forwarded=%v body=%s; want %d", rec.Code, forwarded, rec.Body.String(), tt.want)
			}
		})
	}
}
