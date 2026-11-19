package ownership

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/dockerresource"
)

func TestMiddlewareChecksExistingVolumeOnCreate(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	volume := func(r inspectResult) map[string]map[string]inspectResult {
		return map[string]map[string]inspectResult{string(dockerresource.KindVolume): {"data": r}}
	}
	tests := []struct {
		name      string
		path      string
		body      string
		resources map[string]map[string]inspectResult
		wantCode  int
	}{
		{name: "foreign volume", path: "/volumes/create", body: `{"Name":"data"}`, resources: volume(ownerLabel("job-999")), wantCode: http.StatusForbidden},
		{name: "foreign volume, versioned", path: "/v1.45/volumes/create", body: `{"Name":"data"}`, resources: volume(ownerLabel("job-999")), wantCode: http.StatusForbidden},
		{name: "foreign volume, lowercase key", path: "/volumes/create", body: `{"name":"data"}`, resources: volume(ownerLabel("job-999")), wantCode: http.StatusForbidden},
		{name: "unlabeled volume", path: "/volumes/create", body: `{"Name":"data"}`, resources: volume(inspectResult{labels: map[string]string{}, found: true}), wantCode: http.StatusForbidden},
		{name: "lookup failure", path: "/volumes/create", body: `{"Name":"data"}`, resources: volume(inspectResult{err: errors.New("boom")}), wantCode: http.StatusBadGateway},
		{name: "same owner is idempotent", path: "/volumes/create", body: `{"Name":"data"}`, resources: volume(ownerLabel("job-123")), wantCode: http.StatusOK},
		{name: "absent name", path: "/volumes/create", body: `{"Name":"data"}`, resources: map[string]map[string]inspectResult{}, wantCode: http.StatusOK},
		{name: "generated name", path: "/volumes/create", body: `{}`, resources: volume(ownerLabel("job-999")), wantCode: http.StatusOK},
		{name: "native foreign volume", path: "/libpod/volumes/create", body: `{"Name":"data"}`, resources: volume(ownerLabel("job-999")), wantCode: http.StatusForbidden},
		{name: "native same owner", path: "/v5.0.0/libpod/volumes/create", body: `{"Name":"data","IgnoreIfExists":true}`, resources: volume(ownerLabel("job-123")), wantCode: http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fi := &recordingInspector{resources: tt.resources}
			handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				_, _ = io.WriteString(w, `{"Name":"data","Labels":{"com.sockguard.owner":"job-123"}}`)
			}))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, tt.path, strings.NewReader(tt.body)))
			want := tt.wantCode
			if want == http.StatusOK {
				want = http.StatusCreated
			}
			if rec.Code != want {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, want, rec.Body.String())
			}
		})
	}
}

func TestVolumeCreateResponseMustCarryTheOwnerLabel(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	tests := []struct {
		name     string
		upstream func(http.ResponseWriter)
		wantCode int
		wantLeak string
	}{
		{
			name: "concurrent foreign create",
			upstream: func(w http.ResponseWriter) {
				w.WriteHeader(http.StatusCreated)
				_, _ = io.WriteString(w, `{"Name":"data","Labels":{"com.sockguard.owner":"job-999"},"Options":{"o":"username=admin,password=hunter2"}}`)
			},
			wantCode: http.StatusForbidden,
			wantLeak: "hunter2",
		},
		{
			name: "no labels",
			upstream: func(w http.ResponseWriter) {
				w.WriteHeader(http.StatusCreated)
				_, _ = io.WriteString(w, `{"Name":"data","Labels":null}`)
			},
			wantCode: http.StatusForbidden,
		},
		{
			name: "undecodable",
			upstream: func(w http.ResponseWriter) {
				w.WriteHeader(http.StatusCreated)
				_, _ = io.WriteString(w, `not json`)
			},
			wantCode: http.StatusBadGateway,
		},
		{
			name: "own volume",
			upstream: func(w http.ResponseWriter) {
				w.WriteHeader(http.StatusCreated)
				_, _ = io.WriteString(w, `{"Name":"data","Labels":{"com.sockguard.owner":"job-123"}}`)
			},
			wantCode: http.StatusCreated,
		},
		{
			name: "daemon error passes through",
			upstream: func(w http.ResponseWriter) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = io.WriteString(w, `{"message":"driver failed"}`)
			},
			wantCode: http.StatusInternalServerError,
		},
	}
	for _, path := range []string{"/volumes/create", "/libpod/volumes/create"} {
		for _, tt := range tests {
			t.Run(path+" "+tt.name, func(t *testing.T) {
				t.Parallel()
				fi := &recordingInspector{}
				handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					tt.upstream(w)
				}))
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"Name":"data"}`)))
				if rec.Code != tt.wantCode {
					t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantCode, rec.Body.String())
				}
				if tt.wantLeak != "" && strings.Contains(rec.Body.String(), tt.wantLeak) {
					t.Fatalf("foreign volume data reached the client: %s", rec.Body.String())
				}
			})
		}
	}
}
