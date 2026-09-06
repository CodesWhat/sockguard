package ownership

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/dockerresource"
)

// TestMiddlewareDeniesCrossOwnerVolumeUpdate pins that PUT /volumes/{name},
// the Swarm cluster-volume update, is authorized as a named-resource write
// like every other one. volumeIdentifier excludes only the POST create and
// prune spellings, so the update already routes through checkOwnedResource —
// this fails if that exclusion is ever widened by method or if the PUT
// spelling is carved out, either of which would let a caller rewrite another
// owner's volume spec.
func TestMiddlewareDeniesCrossOwnerVolumeUpdate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		labels     map[string]string
		found      bool
		wantStatus int
	}{
		{
			name:       "another owner's volume is denied",
			labels:     map[string]string{"com.sockguard.owner": "job-999"},
			found:      true,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "an unlabeled volume is denied",
			labels:     map[string]string{},
			found:      true,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "a volume the daemon cannot resolve is denied",
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fi := &recordingInspector{}
			if tt.found {
				fi.resources = map[string]map[string]inspectResult{
					string(dockerresource.KindVolume): {
						"csi-data": {labels: tt.labels, found: true},
					},
				}
			}
			handler := middlewareWithDeps(
				testLogger(),
				Options{Owner: "job-123", LabelKey: "com.sockguard.owner"},
				fi.inspectResource,
				fi.inspectExec,
			)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("cross-owner volume update was forwarded")
			}))

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPut, "/volumes/csi-data?version=7", strings.NewReader(`{"Spec":{"Availability":"drain"}}`))
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if !slices.Contains(fi.calls, resourceInspectCall{kind: dockerresource.KindVolume, id: "csi-data"}) {
				t.Fatalf("inspect calls = %#v, want volume %q", fi.calls, "csi-data")
			}
		})
	}
}

// TestMiddlewareAllowsOwnedVolumeUpdate is the positive half: the owner's own
// cluster-volume update reaches upstream, so the denial above is ownership
// doing its job rather than the whole route being blocked.
func TestMiddlewareAllowsOwnedVolumeUpdate(t *testing.T) {
	t.Parallel()

	fi := &recordingInspector{
		resources: map[string]map[string]inspectResult{
			string(dockerresource.KindVolume): {
				"csi-data": {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true},
			},
		},
	}
	forwarded := false
	handler := middlewareWithDeps(
		testLogger(),
		Options{Owner: "job-123", LabelKey: "com.sockguard.owner"},
		fi.inspectResource,
		fi.inspectExec,
	)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		forwarded = true
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/volumes/csi-data?version=7", strings.NewReader(`{"Spec":{"Availability":"drain"}}`))
	handler.ServeHTTP(rec, req)

	if !forwarded {
		t.Fatalf("owned volume update was not forwarded; status = %d, body: %s", rec.Code, rec.Body.String())
	}
}
