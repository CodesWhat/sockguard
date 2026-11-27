package ownership

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/upstreamflavor"
)

func TestRefuseShadowableSecretName(t *testing.T) {
	tests := []struct {
		name       string
		flavor     upstreamflavor.Flavor
		identifier string
		refused    bool
	}{
		{"short hex on Podman", upstreamflavor.Podman, "b0b0", true},
		{"24 hex on Podman", upstreamflavor.Podman, strings.Repeat("a", 24), true},
		{"full-length ID on Podman", upstreamflavor.Podman, strings.Repeat("a", 25), false},
		{"name with a non-hex letter", upstreamflavor.Podman, "b0b0z", false},
		{"uppercase hex is only a name", upstreamflavor.Podman, "CAFE", false},
		{"short hex on Docker", upstreamflavor.Docker, "b0b0", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := refuseShadowableSecretName(tt.identifier, Options{UpstreamFlavor: tt.flavor})
			if (got != "") != tt.refused {
				t.Errorf("refuseShadowableSecretName(%q) = %q, refused want %v", tt.identifier, got, tt.refused)
			}
		})
	}
}

func TestMutateCompatSecretCreateOwnershipRequest(t *testing.T) {
	tests := []struct {
		name   string
		flavor upstreamflavor.Flavor
		body   string
		deny   bool
	}{
		{"short hex name on Podman", upstreamflavor.Podman, `{"Name":"cafe"}`, true},
		{"short hex name on Docker", upstreamflavor.Docker, `{"Name":"cafe"}`, false},
		{"ordinary name on Podman", upstreamflavor.Podman, `{"Name":"db-password"}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, "http://docker/secrets/create", strings.NewReader(tt.body))
			if err != nil {
				t.Fatal(err)
			}
			refs, err := mutateCompatSecretCreateOwnershipRequest(req, Options{Owner: "team-a", LabelKey: DefaultLabelKey, UpstreamFlavor: tt.flavor})
			if err != nil {
				t.Fatal(err)
			}
			if (refs.denyReason != "") != tt.deny {
				t.Errorf("denyReason = %q, deny want %v", refs.denyReason, tt.deny)
			}
		})
	}
}

func TestCompatSecretRouteRejectsPodmanIDPrefix(t *testing.T) {
	t.Parallel()
	fullID := strings.Repeat("a", 25)
	tests := []struct {
		name       string
		flavor     upstreamflavor.Flavor
		method     string
		target     string
		identifier string
		denied     bool
	}{
		{"podman GET short hex", upstreamflavor.Podman, http.MethodGet, "/secrets/b0b0", "b0b0", true},
		{"podman HEAD short hex", upstreamflavor.Podman, http.MethodHead, "/secrets/b0b0", "b0b0", true},
		{"podman DELETE short hex", upstreamflavor.Podman, http.MethodDelete, "/secrets/b0b0", "b0b0", true},
		{"podman GET versioned short hex", upstreamflavor.Podman, http.MethodGet, "/v1.45/secrets/b0b0", "b0b0", true},
		{"podman HEAD versioned short hex", upstreamflavor.Podman, http.MethodHead, "/v1.45/secrets/b0b0", "b0b0", true},
		{"podman DELETE versioned short hex", upstreamflavor.Podman, http.MethodDelete, "/v1.45/secrets/b0b0", "b0b0", true},
		{"docker short hex reaches owned secret", upstreamflavor.Docker, http.MethodGet, "/secrets/b0b0", "b0b0", false},
		{"podman full-length ID reaches owned secret", upstreamflavor.Podman, http.MethodGet, "/secrets/" + fullID, fullID, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner", UpstreamFlavor: tt.flavor}
			inspector := &recordingInspector{resources: map[string]map[string]inspectResult{
				"secrets": {tt.identifier: {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true}},
			}}
			upstreamCalls := 0
			handler := middlewareWithDeps(testLogger(), opts, inspector.inspectResource, inspector.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				upstreamCalls++
				w.WriteHeader(http.StatusNoContent)
			}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.target, nil))

			if !tt.denied {
				if rec.Code != http.StatusNoContent || upstreamCalls != 1 {
					t.Fatalf("status = %d, upstream calls = %d, want 204 and 1; body: %s", rec.Code, upstreamCalls, rec.Body.String())
				}
				return
			}
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "secret ID prefix") {
				t.Fatalf("deny body = %q, want the ID-prefix refusal", rec.Body.String())
			}
			if len(inspector.calls) != 0 {
				t.Fatalf("inspect calls = %v, want none", inspector.calls)
			}
			if upstreamCalls != 0 {
				t.Fatalf("upstream calls = %d, want 0", upstreamCalls)
			}
		})
	}
}
