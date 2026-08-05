package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/internal/inbound"
	"github.com/codeswhat/sockguard/internal/logging"
)

func TestListenerLabelIsPresentOnEveryDataPlaneMetricFamily(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	handler := registry.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		meta := logging.MetaForRequest(w, r)
		meta.Decision = "deny"
		meta.ReasonCode = "listener_profile_not_allowed"
		meta.NormPath = "/containers/create"
		w.WriteHeader(http.StatusForbidden)
	}))
	req := httptest.NewRequest(http.MethodPost, "/containers/create", nil)
	req = req.WithContext(inbound.WithIdentity(req.Context(), inbound.Identity{
		Name: "ci", Role: inbound.RoleMain, Network: inbound.NetworkUnix,
	}))
	handler.ServeHTTP(httptest.NewRecorder(), req)
	out := renderMetrics(t, registry)

	for _, want := range []string{
		`sockguard_http_requests_total{decision="deny",listener="ci"`,
		`sockguard_http_denied_requests_total{listener="ci"`,
		`sockguard_http_request_duration_seconds_count{decision="deny",listener="ci"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics missing %q:\n%s", want, out)
		}
	}
}

func TestListenerMetricLabelFallsBackToDefault(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	handler := registry.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/_ping", nil))
	if out := renderMetrics(t, registry); !strings.Contains(out, `sockguard_http_requests_total{decision="allow",listener="default"`) {
		t.Fatalf("missing default listener fallback:\n%s", out)
	}
}

func TestListenerUpCanBePreRegisteredAtZeroAndTransitioned(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	for _, identity := range []inbound.Identity{
		{Name: "ci", Role: inbound.RoleMain, Network: inbound.NetworkUnix},
		{Name: "ops", Role: inbound.RoleMain, Network: inbound.NetworkTCP},
		{Name: "admin", Role: inbound.RoleAdmin, Network: inbound.NetworkUnix},
	} {
		registry.SetListenerUp(identity.Name, string(identity.Role), string(identity.Network), false)
	}
	out := renderMetrics(t, registry)
	for _, want := range []string{
		`sockguard_listener_up{listener="admin",network="unix",role="admin"} 0`,
		`sockguard_listener_up{listener="ci",network="unix",role="main"} 0`,
		`sockguard_listener_up{listener="ops",network="tcp",role="main"} 0`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("pre-registered metrics missing %q:\n%s", want, out)
		}
	}

	registry.SetListenerUp("ci", "main", "unix", true)
	if out := renderMetrics(t, registry); !strings.Contains(out, `sockguard_listener_up{listener="ci",network="unix",role="main"} 1`) {
		t.Fatalf("listener transition to up missing:\n%s", out)
	}
}
