package ownership

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/codeswhat/sockguard/v3/app/internal/dockerresource"
	"github.com/codeswhat/sockguard/v3/app/internal/logging"
	"github.com/codeswhat/sockguard/v3/app/internal/upstreamflavor"
)

func TestLibpodImageVolumeRequiresResolvedImageID(t *testing.T) {
	t.Parallel()
	source := strings.Repeat("a", 64)
	child := strings.Repeat("b", 64)
	for _, create := range []string{"containers", "pods"} {
		t.Run(create, func(t *testing.T) {
			tests := []struct {
				name, source, resolved, owner string
				memo, primaryOnly             bool
				want                          int
			}{
				{name: "immutable image", source: source, resolved: source, owner: "job-123", want: http.StatusNoContent},
				{name: "prefixed immutable image", source: "sha256:" + source, resolved: "sha256:" + source, owner: "job-123", want: http.StatusNoContent},
				{name: "manifest list resolves to child", source: source, resolved: child, owner: "job-123", want: http.StatusNotFound},
				{name: "prefixed manifest list", source: "sha256:" + source, resolved: child, owner: "job-123", want: http.StatusNotFound},
				{name: "manifest list with visibility memo", source: source, resolved: child, owner: "job-123", memo: true, want: http.StatusNotFound},
				{name: "missing resolved ID", source: source, owner: "job-123", want: http.StatusNotFound},
				{name: "foreign immutable image", source: source, resolved: source, owner: "other", want: http.StatusForbidden},
				{name: "unowned immutable image", source: source, resolved: source, want: http.StatusNoContent},
				{name: "unowned manifest list", source: source, resolved: child, want: http.StatusNotFound},
				{name: "primary image resolves at create", source: source, resolved: child, owner: "job-123", primaryOnly: true, want: http.StatusNoContent},
			}
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					rt := buildImageTransport(func(r *http.Request) (*http.Response, error) {
						data, _ := json.Marshal(map[string]any{"Id": tt.resolved, "Config": map[string]any{"Labels": map[string]string{"com.sockguard.owner": tt.owner}}})
						return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(data))), Request: r}, nil
					})
					body := map[string]any{"image": "base:latest", "infra_image": "base:latest"}
					if tt.primaryOnly {
						body["image"] = tt.source
						body["infra_image"] = tt.source
					} else {
						body["image_volumes"] = []any{map[string]any{"Source": tt.source, "Destination": "/data"}}
					}
					data, err := json.Marshal(body)
					if err != nil {
						t.Fatal(err)
					}
					forwarded := false
					handler := MiddlewareWithRoundTripper(rt, testLogger(), Options{Owner: "job-123", LabelKey: "com.sockguard.owner", AllowUnownedImages: true, UpstreamFlavor: upstreamflavor.Podman})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded = true; w.WriteHeader(http.StatusNoContent) }))
					req := httptest.NewRequest(http.MethodPost, "/libpod/"+create+"/create", strings.NewReader(string(data)))
					req.Header.Set("Content-Type", "application/json")
					meta := &logging.RequestMeta{}
					if tt.memo {
						meta.RecordInspectedLabels(string(dockerresource.KindImage), tt.source, map[string]string{"com.sockguard.owner": "job-123"}, true)
					}
					req = req.WithContext(logging.WithMeta(req.Context(), meta))
					rec := httptest.NewRecorder()
					handler.ServeHTTP(rec, req)
					if rec.Code != tt.want || forwarded != (tt.want == http.StatusNoContent) {
						t.Fatalf("status=%d forwarded=%v body=%s; want %d", rec.Code, forwarded, rec.Body.String(), tt.want)
					}
				})
			}
		})
	}
}

func TestDecodeImageVolumeIDRejectsInvalidInspect(t *testing.T) {
	t.Parallel()
	source := strings.Repeat("a", 64)
	tests := []struct {
		name string
		body io.Reader
	}{
		{name: "read failure", body: iotest.ErrReader(errors.New("inspect read failed"))},
		{name: "malformed JSON", body: strings.NewReader("{")},
		{name: "oversized body", body: strings.NewReader(strings.Repeat(" ", 1<<20) + "{}")},
		{name: "invalid labels", body: strings.NewReader(`{"Id":"` + source + `","Config":{"Labels":{"owner":1}}}`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			labels, found, err := decodeImageVolumeID(tt.body, source)
			if err == nil || found || labels != nil {
				t.Fatalf("decode = (%v,%v,%v), want error without labels", labels, found, err)
			}
		})
	}
}
