package visibility

import (
	"context"
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

// podman_secrets_test.go covers the Docker-compat GET /secrets on a Podman
// upstream, the compat twin of the GET /libpod/secrets/json refusal
// libpod_coverage_test.go already pins.
//
// Like podman_events_test.go, the point is not that sockguard rewrites the
// body — it does not — but that the request never reaches an upstream that
// cannot answer it. So the fake upstream here is Podman's real behavior:
// compat.ListSecrets runs every secret through utils.IfPassesSecretsFilter,
// whose switch accepts only "name" and "id" and errors on any other key, and
// turns that error into a 500.

// podmanSecretForTest is one entities.SecretInfoReportCompat item, trimmed to
// the fields the policy axes could read.
type podmanSecretForTest struct {
	ID   string `json:"ID"`
	Spec struct {
		Name   string            `json:"Name"`
		Labels map[string]string `json:"Labels"`
	} `json:"Spec"`
}

func podmanSecretForName(name string, labels map[string]string) podmanSecretForTest {
	var s podmanSecretForTest
	s.ID = name + "-id"
	s.Spec.Name = name
	s.Spec.Labels = labels
	return s
}

// podmanSecretsUpstream answers GET /secrets the way Podman v5.8.1 does: 500
// for any filter key that is not name or id, the list otherwise. reached is
// set on every request that arrives.
func podmanSecretsUpstream(t *testing.T, reached *bool, items []podmanSecretForTest) http.Handler {
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
				// utils.InternalServerError over
				// fmt.Errorf("invalid filter %q", key).
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"message": fmt.Sprintf("invalid filter %q", key),
				})
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(items); err != nil {
			t.Fatalf("encode secrets: %v", err)
		}
	})
}

func podmanSecretItemsForTest() []podmanSecretForTest {
	return []podmanSecretForTest{
		podmanSecretForName("visible", map[string]string{"com.sockguard.visible": "true"}),
		podmanSecretForName("hidden", map[string]string{"com.sockguard.visible": "false"}),
	}
}

// TestPodmanCompatSecretListAnswers500ForAnInjectedLabelFilter is the bug this
// file's refusal replaces, held as a positive control on the fake upstream. A
// Docker-flavored visibility policy injects `label` into GET /secrets, which
// is right on dockerd and is a 500 on Podman. If this stops failing, the fake
// upstream no longer models Podman and the refusal tests below prove nothing.
func TestPodmanCompatSecretListAnswers500ForAnInjectedLabelFilter(t *testing.T) {
	t.Parallel()
	reached := false
	handler := middlewareWithDeps(testVisibilityLogger(), Options{
		VisibleResourceLabels: []string{"com.sockguard.visible=true"},
		UpstreamFlavor:        upstreamflavor.Docker,
	}, visibilityDeps{})(podmanSecretsUpstream(t, &reached, podmanSecretItemsForTest()))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1.53/secrets", nil))

	if !reached {
		t.Fatal("the Docker-flavored path must still forward GET /secrets upstream")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d; the fake upstream no longer models Podman's invalid-filter 500", rec.Code, http.StatusInternalServerError)
	}
}

// TestPodmanCompatSecretListRefusedUnderVisibilitySelectors is the fix: with a
// selector-carrying policy and a Podman upstream, GET /secrets gets a 403
// before the daemon is contacted, instead of the 500 above.
func TestPodmanCompatSecretListRefusedUnderVisibilitySelectors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method string
		target string
		opts   Options
	}{
		{
			name:   "default policy on versioned path",
			method: http.MethodGet,
			target: "/v1.53/secrets",
			opts: Options{
				VisibleResourceLabels: []string{"com.sockguard.visible=true"},
				UpstreamFlavor:        upstreamflavor.Podman,
			},
		},
		{
			name:   "bare path",
			method: http.MethodGet,
			target: "/secrets",
			opts: Options{
				VisibleResourceLabels: []string{"com.sockguard.visible=true"},
				UpstreamFlavor:        upstreamflavor.Podman,
			},
		},
		{
			name:   "normalized path",
			method: http.MethodGet,
			target: "/v1.53/containers/../secrets",
			opts: Options{
				VisibleResourceLabels: []string{"com.sockguard.visible=true"},
				UpstreamFlavor:        upstreamflavor.Podman,
			},
		},
		{
			name:   "profile policy",
			method: http.MethodGet,
			target: "/v1.53/secrets",
			opts: Options{
				Profiles: map[string]Policy{
					"watchtower": {VisibleResourceLabels: []string{"com.sockguard.visible=true"}},
				},
				ResolveProfile: func(*http.Request) (string, bool) { return "watchtower", true },
				UpstreamFlavor: upstreamflavor.Podman,
			},
		},
		{
			name:   "head",
			method: http.MethodHead,
			target: "/v1.53/secrets",
			opts: Options{
				VisibleResourceLabels: []string{"com.sockguard.visible=true"},
				UpstreamFlavor:        upstreamflavor.Podman,
			},
		},
		{
			name:   "selectors alongside patterns",
			method: http.MethodGet,
			target: "/v1.53/secrets",
			opts: Options{
				VisibleResourceLabels: []string{"com.sockguard.visible=true"},
				NamePatterns:          []string{"web-*"},
				UpstreamFlavor:        upstreamflavor.Podman,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			reached := false
			handler := middlewareWithDeps(testVisibilityLogger(), tt.opts, visibilityDeps{})(
				podmanSecretsUpstream(t, &reached, podmanSecretItemsForTest()))

			// Warn mode must not forward it, matching every other
			// response-side refusal in this package.
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
			if meta.ReasonCode != reasonCodeVisibilityPodmanSecretList {
				t.Fatalf("meta.ReasonCode = %q, want %q", meta.ReasonCode, reasonCodeVisibilityPodmanSecretList)
			}
			if tt.method == http.MethodGet && !strings.Contains(rec.Body.String(), filter.PodmanCompatSecretListDenyReason) {
				t.Fatalf("body = %s, want the shared deny reason %q", rec.Body.String(), filter.PodmanCompatSecretListDenyReason)
			}
		})
	}
}

// TestPodmanCompatSecretListForwardedWithoutSelectors pins the branch
// handlePodmanCompatEventsRequest's case 0 already takes. A patterns-only
// policy injects nothing into GET /secrets — needsPatternResponseFilter covers
// containers and images only — so there is no 500 to prevent and no isolation
// claim to protect, and refusing would cost a deployment an endpoint for
// nothing.
func TestPodmanCompatSecretListForwardedWithoutSelectors(t *testing.T) {
	t.Parallel()
	reached := false
	handler := middlewareWithDeps(testVisibilityLogger(), Options{
		NamePatterns:   []string{"web-*"},
		UpstreamFlavor: upstreamflavor.Podman,
	}, visibilityDeps{})(podmanSecretsUpstream(t, &reached, podmanSecretItemsForTest()))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1.53/secrets", nil))

	if !reached {
		t.Fatal("a patterns-only policy must forward GET /secrets untouched")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

// TestDockerCompatSecretListKeepsVisibilityLabelInjection is the no-regression
// half. On a Docker upstream the injection is correct and must be unchanged:
// dockerd's swarm secret list ANDs `label` values like every other list.
func TestDockerCompatSecretListKeepsVisibilityLabelInjection(t *testing.T) {
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
	handler := middlewareWithDeps(testVisibilityLogger(), Options{
		VisibleResourceLabels: []string{"com.sockguard.visible=true"},
		UpstreamFlavor:        upstreamflavor.Docker,
	}, visibilityDeps{})(upstream)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1.53/secrets", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if len(forwarded) != 1 || forwarded[0] != "com.sockguard.visible=true" {
		t.Fatalf("forwarded label filter = %v, want [com.sockguard.visible=true]", forwarded)
	}
}

// TestPodmanCompatSecretListRefusalIsScopedToTheListPath proves the flavor
// gate does not swallow the per-secret read. GET /secrets/{id} names one
// secret, which the visibility layer resolves through its ordinary inspect
// path on either engine.
func TestPodmanCompatSecretListRefusalIsScopedToTheListPath(t *testing.T) {
	t.Parallel()
	reached := false
	deps := visibilityDeps{
		inspectResource: func(_ context.Context, _ dockerresource.Kind, _ string) (map[string]string, bool, error) {
			return map[string]string{"com.sockguard.visible": "true"}, true, nil
		},
	}
	handler := middlewareWithDeps(testVisibilityLogger(), Options{
		VisibleResourceLabels: []string{"com.sockguard.visible=true"},
		UpstreamFlavor:        upstreamflavor.Podman,
	}, deps)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ID":"visible-id"}`))
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1.53/secrets/visible-id", nil))

	if !reached || rec.Code != http.StatusOK {
		t.Fatalf("reached = %v status = %d, want true and 200; body: %s", reached, rec.Code, rec.Body.String())
	}
}
