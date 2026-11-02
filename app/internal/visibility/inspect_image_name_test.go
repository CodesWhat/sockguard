package visibility

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Container inspect reports the image ID in the top-level Image field while
// the list reports the name. image_patterns must match the name on both, so a
// container visible in the list stays visible on inspect, logs, top and stats.
func TestImagePatternsMatchImageNameOnInspectShapedBodies(t *testing.T) {
	t.Parallel()

	const imageID = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	tests := []struct {
		name string
		body string
		want bool
	}{
		{name: "docker Config.Image matches", body: `{"Name":"/app","Image":"` + imageID + `","Config":{"Image":"ghcr.io/acme/app:1"}}`, want: true},
		{name: "docker Config.Image does not match", body: `{"Name":"/app","Image":"` + imageID + `","Config":{"Image":"docker.io/other/app:1"}}`, want: false},
		{name: "libpod ImageName matches", body: `{"Name":"app","Image":"` + imageID + `","ImageName":"ghcr.io/acme/app:1","Config":{}}`, want: true},
		{name: "libpod ImageName does not match", body: `{"Name":"app","Image":"` + imageID + `","ImageName":"docker.io/other/app:1","Config":{}}`, want: false},
		{name: "Config.Image wins over ImageName", body: `{"Name":"app","Image":"` + imageID + `","ImageName":"ghcr.io/acme/app:1","Config":{"Image":"docker.io/other/app:1"}}`, want: false},
		{name: "falls back to Image when names are empty", body: `{"Name":"app","Image":"ghcr.io/acme/app:1","Config":{}}`, want: true},
		{name: "image ID alone never matches", body: `{"Name":"app","Image":"` + imageID + `","Config":{}}`, want: false},
		{name: "no image reference stays hidden", body: `{"Name":"app","Config":{}}`, want: false},
	}

	paths := []string{
		"/v1.53/containers/abc/json",
		"/v1.53/containers/abc/logs",
		"/v1.53/containers/abc/top",
		"/v1.53/containers/abc/stats",
		"/v6.1.4/libpod/containers/abc/json",
	}

	for _, tt := range tests {
		for _, path := range paths {
			t.Run(tt.name+" "+path, func(t *testing.T) {
				t.Parallel()
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, tt.body)
				}))
				t.Cleanup(srv.Close)
				ins := upstreamInspector{client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					r2 := r.Clone(r.Context())
					r2.URL.Scheme = "http"
					r2.URL.Host = srv.Listener.Addr().String()
					return srv.Client().Transport.RoundTrip(r2)
				})}}

				deps := newVisibilityDepsClient(ins.client)
				reached := false
				handler := middlewareWithDeps(testVisibilityLogger(), Options{ImagePatterns: []string{"ghcr.io/acme/*"}}, deps)(
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reached = true; w.WriteHeader(http.StatusNoContent) }))
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

				wantStatus := http.StatusNotFound
				if tt.want {
					wantStatus = http.StatusNoContent
				}
				if reached != tt.want || rec.Code != wantStatus {
					t.Fatalf("reached=%v status=%d, want reached=%v status=%d", reached, rec.Code, tt.want, wantStatus)
				}
			})
		}
	}
}
