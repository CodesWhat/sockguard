package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
	"github.com/codeswhat/sockguard/v3/app/internal/reload"
)

func adminReloadFixture(t *testing.T, initialCIDRs []string) (*reloadCoordinatorFixture, *reload.SwappableHandler, config.Config) {
	t.Helper()
	initial := config.Defaults()
	initial.Admin.Enabled = true
	initial.Admin.Listen.Address = "127.0.0.1:0"
	initial.Clients.AllowedCIDRs = initialCIDRs
	f := newReloadCoordinatorFixture(t, &initial)
	adminSwappable := reload.NewSwappableHandler(buildAdminHandlerChain(&initial, newDiscardLogger(), nil, nil))
	f.coordinator.setAdminSwappable(adminSwappable)
	return f, adminSwappable, initial
}

func adminStatusFrom(h http.Handler, remote string) int {
	req := httptest.NewRequest(http.MethodGet, "/no-such-admin-path", nil)
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestReloadAdminChainNarrowsAllowedCIDRs(t *testing.T) {
	f, admin, initial := adminReloadFixture(t, []string{"10.0.0.0/8", "192.168.0.0/16"})
	if got := adminStatusFrom(admin, "192.168.1.5:1000"); got != http.StatusNotFound {
		t.Fatalf("pre-reload allowed source status = %d, want 404", got)
	}

	candidate := initial
	candidate.Clients.AllowedCIDRs = []string{"10.0.0.0/8"}
	f.loadCfg = &candidate
	f.coordinator.reload()

	if got := adminStatusFrom(admin, "192.168.1.5:1000"); got != http.StatusForbidden {
		t.Fatalf("removed CIDR status = %d, want 403", got)
	}
	if got := adminStatusFrom(admin, "10.1.2.3:1000"); got != http.StatusNotFound {
		t.Fatalf("retained CIDR status = %d, want 404 (admitted)", got)
	}
}

func TestReloadAdminChainWidensFromEmptyAllowlist(t *testing.T) {
	f, admin, initial := adminReloadFixture(t, nil)
	if got := adminStatusFrom(admin, "203.0.113.9:1000"); got != http.StatusNotFound {
		t.Fatalf("empty allowlist status = %d, want 404 (pass-through)", got)
	}

	candidate := initial
	candidate.Clients.AllowedCIDRs = []string{"10.0.0.0/8"}
	f.loadCfg = &candidate
	f.coordinator.reload()

	if got := adminStatusFrom(admin, "203.0.113.9:1000"); got != http.StatusForbidden {
		t.Fatalf("outside enforced allowlist status = %d, want 403", got)
	}
	if got := adminStatusFrom(admin, "10.0.0.7:1000"); got != http.StatusNotFound {
		t.Fatalf("inside enforced allowlist status = %d, want 404", got)
	}

	// Widening: add the previously refused network.
	wider := initial
	wider.Clients.AllowedCIDRs = []string{"10.0.0.0/8", "203.0.113.0/24"}
	f.loadCfg = &wider
	f.coordinator.reload()
	if got := adminStatusFrom(admin, "203.0.113.9:1000"); got != http.StatusNotFound {
		t.Fatalf("widened allowlist status = %d, want 404", got)
	}
}

func TestReloadAdminChainUnchangedByRejectedReload(t *testing.T) {
	f, admin, initial := adminReloadFixture(t, []string{"10.0.0.0/8", "192.168.0.0/16"})
	before := fmt.Sprintf("%p", admin.Current())
	mainBefore := fmt.Sprintf("%p", f.swappable.Current())

	candidate := initial
	candidate.Clients.AllowedCIDRs = []string{"10.0.0.0/8"}
	f.loadCfg = &candidate
	f.validateErr = http.ErrAbortHandler // any validation failure rejects the reload
	f.coordinator.reload()

	if fmt.Sprintf("%p", admin.Current()) != before {
		t.Fatal("admin chain swapped by a rejected reload")
	}
	if fmt.Sprintf("%p", f.swappable.Current()) != mainBefore {
		t.Fatal("main chain swapped by a rejected reload")
	}
	if got := adminStatusFrom(admin, "192.168.1.5:1000"); got != http.StatusNotFound {
		t.Fatalf("source from original allowlist status = %d, want 404", got)
	}
}
