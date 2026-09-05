package ownership

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/dockerfilters"
	"github.com/codeswhat/sockguard/app/internal/dockerresource"
	"github.com/codeswhat/sockguard/app/internal/filter"
	"github.com/codeswhat/sockguard/app/internal/logging"
	"github.com/codeswhat/sockguard/app/internal/upstreamflavor"
)

// podman_secrets_test.go is the owner-isolation half of the Docker-compat
// GET /secrets refusal on a Podman upstream. The visibility half lives in
// internal/visibility/podman_secrets_test.go and the both-layers case in
// label_filter_compose_test.go.

// podmanSecretsUpstreamForTest answers GET /secrets the way Podman v5.8.1
// does: compat.ListSecrets runs abi.SecretList, which runs every secret
// through utils.IfPassesSecretsFilter, whose switch accepts only "name" and
// "id" and returns fmt.Errorf("invalid filter %q", key) on anything else;
// utils.InternalServerError turns that into a 500.
func podmanSecretsUpstreamForTest(t *testing.T, reached *bool) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if reached != nil {
			*reached = true
		}
		decoded, err := dockerfilters.Decode(r.URL.Query().Get("filters"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for key := range decoded {
			switch strings.ToLower(key) {
			case "name", "id":
			default:
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"message": fmt.Sprintf("invalid filter %q", key),
				})
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"ID":"s-1","Spec":{"Name":"api-key","Labels":{}}}]`))
	})
}

// TestPodmanCompatSecretListAnswers500ForTheOwnerLabelFilter is the bug, held
// as a positive control on the fake upstream. Owner isolation injects the
// owner label into GET /secrets through needsOwnerFilter, which is right on
// dockerd and a 500 on Podman. If this stops failing, the fake upstream no
// longer models Podman.
func TestPodmanCompatSecretListAnswers500ForTheOwnerLabelFilter(t *testing.T) {
	t.Parallel()
	reached := false
	handler := middlewareWithDeps(testLogger(), Options{
		Owner:          "team-a",
		UpstreamFlavor: upstreamflavor.Docker,
	}, fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(podmanSecretsUpstreamForTest(t, &reached))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1.53/secrets", nil)
	req = req.WithContext(logging.WithMeta(req.Context(), &logging.RequestMeta{}))
	handler.ServeHTTP(rec, req)

	if !reached {
		t.Fatal("the Docker-flavored path must still forward GET /secrets upstream")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d; the fake upstream no longer models Podman's invalid-filter 500", rec.Code, http.StatusInternalServerError)
	}
}

// TestPodmanCompatSecretListRefusedUnderOwnerIsolation is the fix: an
// owner-only deployment on a Podman upstream gets a 403 before the daemon is
// contacted, rather than the 500 above.
func TestPodmanCompatSecretListRefusedUnderOwnerIsolation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method string
		target string
	}{
		{name: "versioned path", method: http.MethodGet, target: "/v1.53/secrets"},
		{name: "bare path", method: http.MethodGet, target: "/secrets"},
		{name: "normalized path", method: http.MethodGet, target: "/v1.53/containers/../secrets"},
		{name: "podman version grammar", method: http.MethodGet, target: "/v5.8.1/secrets"},
		{name: "head", method: http.MethodHead, target: "/v1.53/secrets"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			reached := false
			handler := middlewareWithDeps(testLogger(), Options{
				Owner:          "team-a",
				UpstreamFlavor: upstreamflavor.Podman,
			}, fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(podmanSecretsUpstreamForTest(t, &reached))

			// Warn mode must not forward it, matching
			// denyUnscopeableLibpodRead.
			meta := &logging.RequestMeta{RolloutMode: "warn"}
			req := httptest.NewRequest(tt.method, tt.target, nil)
			req = req.WithContext(logging.WithMeta(req.Context(), meta))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if reached {
				t.Fatal("the refused request reached Podman's secret list")
			}
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
			}
			if meta.ReasonCode != reasonCodeOwnerPodmanSecretList {
				t.Fatalf("meta.ReasonCode = %q, want %q", meta.ReasonCode, reasonCodeOwnerPodmanSecretList)
			}
			if tt.method == http.MethodGet && !strings.Contains(rec.Body.String(), filter.PodmanCompatSecretListDenyReason) {
				t.Fatalf("body = %s, want the shared deny reason %q", rec.Body.String(), filter.PodmanCompatSecretListDenyReason)
			}
		})
	}
}

// TestPodmanCompatSecretListInertWithoutOwnerIsolation proves the refusal
// costs nothing to a deployment that configures no owner: with Owner empty the
// middleware is a no-op, so nothing is injected and nothing is refused.
func TestPodmanCompatSecretListInertWithoutOwnerIsolation(t *testing.T) {
	t.Parallel()
	reached := false
	handler := middlewareWithDeps(testLogger(), Options{
		UpstreamFlavor: upstreamflavor.Podman,
	}, fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(podmanSecretsUpstreamForTest(t, &reached))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1.53/secrets", nil))

	if !reached || rec.Code != http.StatusOK {
		t.Fatalf("reached = %v status = %d, want true and 200; body: %s", reached, rec.Code, rec.Body.String())
	}
}

// TestDockerCompatSecretListKeepsOwnerLabelInjection is the no-regression
// half: on a Docker upstream the owner label still reaches the daemon.
func TestDockerCompatSecretListKeepsOwnerLabelInjection(t *testing.T) {
	t.Parallel()
	var forwarded []string
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decoded, err := dockerfilters.Decode(r.URL.Query().Get("filters"))
		if err != nil {
			t.Fatalf("decode forwarded filters: %v", err)
		}
		forwarded = decoded["label"]
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	})
	handler := middlewareWithDeps(testLogger(), Options{
		Owner:          "team-a",
		UpstreamFlavor: upstreamflavor.Docker,
	}, fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(upstream)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1.53/secrets", nil)
	req = req.WithContext(logging.WithMeta(req.Context(), &logging.RequestMeta{}))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if len(forwarded) != 1 || forwarded[0] != ownerLabelForTest+"=team-a" {
		t.Fatalf("forwarded label filter = %v, want [%s=team-a]", forwarded, ownerLabelForTest)
	}
}

// TestPodmanCompatSecretRefusalIsScopedToTheListPath proves the flavor gate
// does not swallow POST /secrets/create or the per-secret reads, which name a
// resource the ownership layer already checks.
func TestPodmanCompatSecretRefusalIsScopedToTheListPath(t *testing.T) {
	t.Parallel()
	reached := false
	inspector := fakeInspector{resources: map[string]map[string]inspectResult{
		string(dockerresource.KindSecret): {"s-1": {labels: map[string]string{ownerLabelForTest: "team-a"}, found: true}},
	}}
	handler := middlewareWithDeps(testLogger(), Options{
		Owner:          "team-a",
		UpstreamFlavor: upstreamflavor.Podman,
	}, inspector.inspectResource, inspector.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ID":"s-1"}`))
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1.53/secrets/s-1", nil)
	req = req.WithContext(logging.WithMeta(req.Context(), &logging.RequestMeta{}))
	handler.ServeHTTP(rec, req)

	if !reached || rec.Code != http.StatusOK {
		t.Fatalf("reached = %v status = %d, want true and 200; body: %s", reached, rec.Code, rec.Body.String())
	}
}
