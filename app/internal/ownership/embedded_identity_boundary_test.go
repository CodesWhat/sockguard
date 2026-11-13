package ownership

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/upstreamflavor"
)

func TestCompatCreateReservedNetworkNamesFollowEngineFlavor(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		flavor upstreamflavor.Flavor
		want   int
	}{
		{upstreamflavor.Docker, http.StatusAccepted},
		{upstreamflavor.Podman, http.StatusForbidden},
	} {
		for _, network := range []string{"ingress", "docker_gwbridge"} {
			t.Run(string(tc.flavor)+"/"+network, func(t *testing.T) {
				t.Parallel()
				networkInspects := 0
				rt := buildImageTransport(func(r *http.Request) (*http.Response, error) {
					body := `{"Config":{"Labels":{"` + DefaultLabelKey + `":"team-a"}}}`
					if r.URL.Path == "/networks/"+network {
						networkInspects++
						body = `{"Name":"` + network + `","Labels":{"` + DefaultLabelKey + `":"team-b"}}`
					} else if r.URL.Path != "/images/alpine/json" {
						t.Errorf("unexpected inspect: %s", r.URL.Path)
					}
					return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
				})
				forwarded := false
				handler := MiddlewareWithRoundTripper(rt, testLogger(), Options{Owner: "team-a", LabelKey: DefaultLabelKey, UpstreamFlavor: tc.flavor})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					forwarded = true
					w.WriteHeader(http.StatusAccepted)
				}))
				req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(`{"Image":"alpine","HostConfig":{"NetworkMode":"`+network+`"}}`))
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				wantInspects := 0
				if tc.flavor == upstreamflavor.Podman {
					wantInspects = 1
				}
				if rec.Code != tc.want || forwarded != (tc.want == http.StatusAccepted) || networkInspects != wantInspects {
					t.Fatalf("status=%d forwarded=%v network inspects=%d, want status=%d inspects=%d; body=%s", rec.Code, forwarded, networkInspects, tc.want, wantInspects, rec.Body.String())
				}
			})
		}
	}
}

func TestNativeCreateKeepsImageAndPodWithSameIdentifierDistinct(t *testing.T) {
	t.Parallel()
	for _, podOwner := range []string{"team-a", "team-b"} {
		t.Run(podOwner, func(t *testing.T) {
			t.Parallel()
			podInspects := 0
			rt := buildImageTransport(func(r *http.Request) (*http.Response, error) {
				body := `{"Config":{"Labels":{"` + DefaultLabelKey + `":"team-a"}}}`
				if r.URL.Path == "/libpod/pods/shared/json" {
					podInspects++
					body = `{"Labels":{"` + DefaultLabelKey + `":"` + podOwner + `"}}`
				} else if r.URL.Path != "/images/shared/json" {
					t.Errorf("unexpected inspect: %s", r.URL.Path)
				}
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
			})
			forwarded := false
			handler := MiddlewareWithRoundTripper(rt, testLogger(), Options{Owner: "team-a", LabelKey: DefaultLabelKey, UpstreamFlavor: upstreamflavor.Podman})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				forwarded = true
				w.WriteHeader(http.StatusAccepted)
			}))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/libpod/containers/create", strings.NewReader(`{"image":"shared","pod":"shared"}`)))
			want := http.StatusAccepted
			if podOwner != "team-a" {
				want = http.StatusForbidden
			}
			if rec.Code != want || forwarded != (want == http.StatusAccepted) || podInspects != 1 {
				t.Fatalf("status=%d forwarded=%v pod inspects=%d, want status=%d; body=%s", rec.Code, forwarded, podInspects, want, rec.Body.String())
			}
		})
	}
}
