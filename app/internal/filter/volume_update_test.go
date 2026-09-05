package filter

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestVolumeUpdateInspect pins the ClusterVolumeSpec gates on Docker's
// PUT /volumes/{name}. Every field name here is the wire spelling moby
// actually sends: volume.ClusterVolumeSpec carries no explicit JSON names, so
// the keys are the Go field names.
func TestVolumeUpdateInspect(t *testing.T) {
	const path = "/volumes/csi-data"

	tests := []struct {
		name       string
		opts       VolumeOptions
		body       string
		wantReason string
	}{
		{
			name:       "denies rewriting cluster volume secrets by default",
			body:       `{"Spec":{"Secrets":[{"Key":"password","Secret":"other-teams-secret"}]}}`,
			wantReason: "volume update denied: cluster volume secrets are not allowed",
		},
		{
			name:       "denies draining the volume by default",
			body:       `{"Spec":{"Availability":"drain"}}`,
			wantReason: "volume update denied: cluster volume availability changes are not allowed",
		},
		{
			name:       "denies a group change by default",
			body:       `{"Spec":{"Group":"other-group"}}`,
			wantReason: "volume update denied: cluster volume group changes are not allowed",
		},
		{
			name:       "denies an access mode change by default",
			body:       `{"Spec":{"AccessMode":{"Scope":"multi","Sharing":"all"}}}`,
			wantReason: "volume update denied: cluster volume access mode changes are not allowed",
		},
		{
			name:       "denies a capacity change by default",
			body:       `{"Spec":{"CapacityRange":{"RequiredBytes":1073741824}}}`,
			wantReason: "volume update denied: cluster volume capacity changes are not allowed",
		},
		{
			name:       "denies a topology change by default",
			body:       `{"Spec":{"AccessibilityRequirements":{"Requisite":[{"Segments":{"rack":"r2"}}]}}}`,
			wantReason: "volume update denied: cluster volume topology changes are not allowed",
		},
		{
			name: "allows a well-formed availability update when configured",
			opts: VolumeOptions{AllowClusterVolumeUpdates: true},
			body: `{"Spec":{"Availability":"active"}}`,
		},
		{
			name: "allows a well-formed capacity update when configured",
			opts: VolumeOptions{AllowClusterVolumeUpdates: true},
			body: `{"Spec":{"CapacityRange":{"RequiredBytes":1073741824,"LimitBytes":2147483648}}}`,
		},
		{
			name: "allows secrets only under their own flag",
			opts: VolumeOptions{AllowClusterVolumeSecrets: true},
			body: `{"Spec":{"Secrets":[{"Key":"password","Secret":"my-secret"}]}}`,
		},
		{
			// allow_cluster_volume_updates is documented as NOT admitting
			// Secrets. Pin that, so widening the broad flag to cover the
			// escalation field is a test failure rather than a quiet change.
			name:       "the broad flag does not admit secrets",
			opts:       VolumeOptions{AllowClusterVolumeUpdates: true},
			body:       `{"Spec":{"Secrets":[{"Key":"password","Secret":"other-teams-secret"}]}}`,
			wantReason: "volume update denied: cluster volume secrets are not allowed",
		},
		{
			name: "allows a body with no Spec at all",
			body: `{}`,
		},
		{
			name: "allows an explicitly null Spec",
			body: `{"Spec":null}`,
		},
		{
			name: "allows an empty Spec object",
			body: `{"Spec":{}}`,
		},
		{
			name: "treats explicitly null spec fields as absent",
			body: `{"Spec":{"AccessMode":null,"CapacityRange":null,"AccessibilityRequirements":null,"Secrets":null,"Availability":null,"Group":null}}`,
		},
		{
			name:       "fails closed on a field-level type mismatch",
			body:       `{"Spec":{"Availability":42}}`,
			wantReason: "volume update denied: request body could not be inspected",
		},
		{
			name:       "fails closed when Spec is not an object",
			body:       `{"Spec":"drain"}`,
			wantReason: "volume update denied: request body could not be inspected",
		},
		{
			// encoding/json matches field names case-insensitively, so the
			// lowercase spelling a hand-rolled client might send decodes on
			// the daemon and must be gated here too.
			name:       "denies the case-folded spelling moby also accepts",
			body:       `{"spec":{"availability":"drain"}}`,
			wantReason: "volume update denied: cluster volume availability changes are not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := newVolumePolicy(tt.opts)
			req := httptest.NewRequest(http.MethodPut, path+"?version=7", strings.NewReader(tt.body))
			reason, err := policy.inspectUpdate(testLogger(), req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspectUpdate() error = %v", err)
			}
			if reason != tt.wantReason {
				t.Fatalf("inspectUpdate() reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

func TestVolumeUpdateInspectHandlesMalformedJSON(t *testing.T) {
	policy := newVolumePolicy(VolumeOptions{})
	req := httptest.NewRequest(http.MethodPut, "/volumes/csi-data", bytes.NewBufferString(`{"Spec":{`))

	reason, err := policy.inspectUpdate(testLogger(), req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspectUpdate() error = %v", err)
	}
	const wantReason = "volume update denied: request body could not be inspected"
	if reason != wantReason {
		t.Fatalf("inspectUpdate() reason = %q, want %q", reason, wantReason)
	}
}

func TestVolumeUpdateInspectCapsOversizedBody(t *testing.T) {
	policy := newVolumePolicy(VolumeOptions{})
	req := httptest.NewRequest(http.MethodPut, "/volumes/csi-data", bytes.NewReader(bytes.Repeat([]byte{'x'}, maxVolumeBodyBytes+1)))

	reason, err := policy.inspectUpdate(testLogger(), req, NormalizePath(req.URL.Path))
	if reason != "" {
		t.Fatalf("inspectUpdate() reason = %q, want empty", reason)
	}
	rejection, ok := requestRejectionFromError(err)
	if !ok {
		t.Fatalf("inspectUpdate() error = %v, want request rejection", err)
	}
	if rejection.status != http.StatusRequestEntityTooLarge {
		t.Fatalf("rejection status = %d, want %d", rejection.status, http.StatusRequestEntityTooLarge)
	}
	if !strings.HasPrefix(rejection.reason, "volume update denied: request body exceeds") {
		t.Fatalf("rejection reason = %q, want oversize denial", rejection.reason)
	}
}

func TestVolumeUpdateInspectIgnoresNonMatchingRequests(t *testing.T) {
	policy := newVolumePolicy(VolumeOptions{})

	t.Run("nil request", func(t *testing.T) {
		reason, err := policy.inspectUpdate(testLogger(), nil, "/volumes/csi-data")
		if err != nil || reason != "" {
			t.Fatalf("inspectUpdate(nil) = (%q, %v), want empty", reason, err)
		}
	})

	t.Run("nil body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/volumes/csi-data", nil)
		req.Body = nil
		reason, err := policy.inspectUpdate(testLogger(), req, "/volumes/csi-data")
		if err != nil || reason != "" {
			t.Fatalf("inspectUpdate(nil body) = (%q, %v), want empty", reason, err)
		}
	})

	t.Run("empty body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/volumes/csi-data", bytes.NewReader(nil))
		reason, err := policy.inspectUpdate(testLogger(), req, "/volumes/csi-data")
		if err != nil || reason != "" {
			t.Fatalf("inspectUpdate(empty body) = (%q, %v), want empty", reason, err)
		}
	})

	t.Run("the volume list path", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/volumes", strings.NewReader(`{"Spec":{"Availability":"drain"}}`))
		reason, err := policy.inspectUpdate(testLogger(), req, "/volumes")
		if err != nil || reason != "" {
			t.Fatalf("inspectUpdate() = (%q, %v), want empty", reason, err)
		}
	})

	t.Run("a non-PUT method on the same path", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/volumes/csi-data", strings.NewReader(`{"Spec":{"Availability":"drain"}}`))
		reason, err := policy.inspectUpdate(testLogger(), req, "/volumes/csi-data")
		if err != nil || reason != "" {
			t.Fatalf("inspectUpdate() = (%q, %v), want empty", reason, err)
		}
	})
}

// TestVolumeCreateInspectorIgnoresTheUpdatePath is the other half of the
// routing split: the create inspector must not start reading update bodies,
// so a ClusterVolumeSpec can never be judged against the driver/driver-opts
// gates that were written for volume.CreateOptions.
func TestVolumeCreateInspectorIgnoresTheUpdatePath(t *testing.T) {
	policy := newVolumePolicy(VolumeOptions{})
	req := httptest.NewRequest(http.MethodPut, "/volumes/csi-data", strings.NewReader(`{"Spec":{"Availability":"drain"}}`))
	reason, err := policy.inspect(testLogger(), req, NormalizePath(req.URL.Path))
	if err != nil || reason != "" {
		t.Fatalf("inspect() = (%q, %v), want empty", reason, err)
	}
}

// TestVolumeUpdatePathCoversTheWholeMobyRoute pins the matcher against the
// route moby actually registers, PUT /volumes/{name:.*}. The create and prune
// spellings resolve to putVolumesUpdate under PUT because no PUT route exists
// for either, so leaving them out would be two uninspected doors into the
// same handler.
func TestVolumeUpdatePathCoversTheWholeMobyRoute(t *testing.T) {
	matching := []string{
		"/volumes/csi-data",
		"/volumes/create",
		"/volumes/prune",
		"/volumes/team/csi-data",
		NormalizePath("/v1.53/volumes/csi-data"),
	}
	for _, path := range matching {
		if !isVolumeUpdatePath(path) {
			t.Errorf("isVolumeUpdatePath(%q) = false, want true", path)
		}
	}

	nonMatching := []string{"/volumes", "/volumes/", "/containers/abc/archive", "/libpod/volumes/create"}
	for _, path := range nonMatching {
		if isVolumeUpdatePath(path) {
			t.Errorf("isVolumeUpdatePath(%q) = true, want false", path)
		}
	}
}

// TestVolumeUpdateIsWiredIntoTheMiddleware drives the real filter chain, so it
// fails if compileRuntimePolicy's table or matchesVolumeUpdateInspection stops
// routing PUT /volumes/{name} at the inspector — the half a method-level test
// cannot see. It also pins that the update path reads the SAME
// request_body.volume config the create path does.
func TestVolumeUpdateIsWiredIntoTheMiddleware(t *testing.T) {
	allowAll, err := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionAllow, Index: 0})
	if err != nil {
		t.Fatalf("CompileRule() error = %v", err)
	}

	tests := []struct {
		name       string
		opts       VolumeOptions
		target     string
		body       string
		wantStatus int
	}{
		{
			name:       "a secret rewrite is denied",
			target:     "/volumes/csi-data",
			body:       `{"Spec":{"Secrets":[{"Key":"password","Secret":"other-teams-secret"}]}}`,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "a drain is denied",
			target:     "/volumes/csi-data",
			body:       `{"Spec":{"Availability":"drain"}}`,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "a versioned drain is denied",
			target:     "/v1.53/volumes/csi-data",
			body:       `{"Spec":{"Availability":"drain"}}`,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "an oversized body is rejected before it reaches upstream",
			target:     "/volumes/csi-data",
			body:       `{"Spec":{"Group":"` + strings.Repeat("x", maxVolumeBodyBytes) + `"}}`,
			wantStatus: http.StatusRequestEntityTooLarge,
		},
		{
			name:       "a configured availability update reaches upstream",
			opts:       VolumeOptions{AllowClusterVolumeUpdates: true},
			target:     "/volumes/csi-data",
			body:       `{"Spec":{"Availability":"active"}}`,
			wantStatus: http.StatusOK,
		},
		{
			name:       "a no-op update reaches upstream",
			target:     "/volumes/csi-data",
			body:       `{}`,
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reached := false
			inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				reached = true
				w.WriteHeader(http.StatusOK)
			})
			handler := MiddlewareWithOptions([]*CompiledRule{allowAll}, testLogger(), Options{
				PolicyConfig: PolicyConfig{
					DenyResponseVerbosity: DenyResponseVerbosityVerbose,
					Volume:                tt.opts,
				},
			})(inner)

			req := httptest.NewRequest(http.MethodPut, tt.target+"?version=7", strings.NewReader(tt.body))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if wantReached := tt.wantStatus == http.StatusOK; reached != wantReached {
				t.Fatalf("upstream reached = %v, want %v", reached, wantReached)
			}
		})
	}
}

// TestVolumeUpdateDoesNotDisturbContainerArchive pins the one collision the
// severity-bucket walk could produce: PUT /containers/{id}/archive and
// PUT /volumes/{name} are both PUT inspectors, and inspectAllowedRequest runs
// only the highest-severity non-empty bucket. If the volume matcher ever
// widened to cover an archive path, archive inspection would keep running
// (High beats Medium) but the volume body would go unread, so pin that
// neither matcher claims the other's route.
func TestVolumeUpdateDoesNotDisturbContainerArchive(t *testing.T) {
	if matchesVolumeUpdateInspection("/containers/abc/archive") {
		t.Error("matchesVolumeUpdateInspection claimed the container archive path")
	}
	if matchesContainerArchiveInspection("/volumes/csi-data") {
		t.Error("matchesContainerArchiveInspection claimed the volume update path")
	}
}
