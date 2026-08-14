package cmd

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/app/internal/clientacl"
	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/inbound"
	"github.com/codeswhat/sockguard/app/internal/logging"
	"github.com/codeswhat/sockguard/app/internal/reload"
)

func admissionTestConfig() config.Config {
	cfg := config.Defaults()
	cfg.Listeners = []config.ListenerConfig{
		{
			Name: "ci",
			ListenConfig: config.ListenConfig{
				Socket:     "/run/ci.sock",
				SocketMode: config.HardenedListenSocketMode,
			},
			AllowedProfiles: []string{"ci"},
		},
		{
			Name: "ops",
			ListenConfig: config.ListenConfig{
				Socket:     "/run/ops.sock",
				SocketMode: config.HardenedListenSocketMode,
			},
			AllowedProfiles: []string{"ops"},
		},
	}
	return cfg
}

func profiledAdmissionHandler(cfg *config.Config, profile string, next http.Handler) http.Handler {
	gate := withListenerAdmission(cfg)(next)
	if profile == "" {
		return gate
	}
	return clientacl.Middleware("", slog.New(slog.NewTextHandler(io.Discard, nil)), clientacl.Options{
		Profiles: clientacl.ProfileOptions{DefaultProfile: profile},
	})(gate)
}

func admissionRequest(name string, role inbound.Role) (*http.Request, *logging.RequestMeta) {
	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	meta := &logging.RequestMeta{}
	ctx := logging.WithMeta(req.Context(), meta)
	if name != "" {
		ctx = inbound.WithIdentity(ctx, inbound.Identity{Name: name, Role: role, Network: inbound.NetworkUnix})
	}
	return req.WithContext(ctx), meta
}

func TestListenerAdmissionSameProfileIsScopedByListener(t *testing.T) {
	t.Parallel()

	cfg := admissionTestConfig()
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := profiledAdmissionHandler(&cfg, "ci", next)

	for _, tc := range []struct {
		listener string
		wantCode int
		wantWhy  string
	}{
		{listener: "ci", wantCode: http.StatusOK},
		{listener: "ops", wantCode: http.StatusForbidden, wantWhy: "listener_profile_not_allowed"},
	} {
		t.Run(tc.listener, func(t *testing.T) {
			req, meta := admissionRequest(tc.listener, inbound.RoleMain)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tc.wantCode, rec.Body.String())
			}
			if meta.ReasonCode != tc.wantWhy {
				t.Fatalf("reason_code = %q, want %q", meta.ReasonCode, tc.wantWhy)
			}
		})
	}
}

func TestListenerAdmissionWildcardIncludesUnprofiledClients(t *testing.T) {
	t.Parallel()

	cfg := admissionTestConfig()
	cfg.Listeners[0].AllowedProfiles = []string{config.WildcardProfile}
	for _, profile := range []string{"", "ops"} {
		name := "unprofiled"
		if profile != "" {
			name = "profiled"
		}
		t.Run(name, func(t *testing.T) {
			handler := profiledAdmissionHandler(&cfg, profile, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			req, _ := admissionRequest("ci", inbound.RoleMain)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 for %s wildcard client; body=%s", rec.Code, name, rec.Body.String())
			}
		})
	}
}

func TestListenerAdmissionMissingUnknownAndWrongRoleFailClosed(t *testing.T) {
	t.Parallel()

	cfg := admissionTestConfig()
	handler := profiledAdmissionHandler(&cfg, "ci", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	tests := []struct {
		name     string
		listener string
		role     inbound.Role
		wantWhy  string
	}{
		{name: "missing", wantWhy: "listener_identity_missing"},
		{name: "unknown", listener: "unknown", role: inbound.RoleMain, wantWhy: "listener_config_missing"},
		{name: "admin role", listener: "ci", role: inbound.RoleAdmin, wantWhy: "listener_identity_missing"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, meta := admissionRequest(tc.listener, tc.role)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
			}
			if meta.ReasonCode != tc.wantWhy {
				t.Fatalf("reason_code = %q, want %q", meta.ReasonCode, tc.wantWhy)
			}
		})
	}
}

func TestListenerAdmissionCannotBleedProfilesAcrossListeners(t *testing.T) {
	t.Parallel()

	cfg := admissionTestConfig()
	handler := profiledAdmissionHandler(&cfg, "ci", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	const requests = 64
	var wg sync.WaitGroup
	errs := make(chan string, requests*2)
	for i := 0; i < requests; i++ {
		for _, tc := range []struct {
			name string
			want int
		}{{name: "ci", want: http.StatusOK}, {name: "ops", want: http.StatusForbidden}} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				req, _ := admissionRequest(tc.name, inbound.RoleMain)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code != tc.want {
					errs <- tc.name
				}
			}()
		}
	}
	wg.Wait()
	close(errs)
	for listener := range errs {
		t.Errorf("listener %s observed a response from the other listener's profile scope", listener)
	}
}

func TestMountOnGateScopesInBandAdminRoutes(t *testing.T) {
	t.Parallel()

	adminMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/admin" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })

	cfg := admissionTestConfig()
	cfg.Admin.Enabled = true
	cfg.Admin.MountOn = "ci"
	handler := mountOnGate(&cfg, adminMiddleware)(next)

	for _, tc := range []struct {
		name, path string
		want       int
	}{
		{name: "ci", path: "/admin", want: http.StatusNoContent},
		{name: "ops", path: "/admin", want: http.StatusTeapot},
		{name: "ci", path: "/docker", want: http.StatusTeapot},
	} {
		t.Run(tc.name+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req = req.WithContext(inbound.WithIdentity(req.Context(), inbound.Identity{Name: tc.name, Role: inbound.RoleMain, Network: inbound.NetworkUnix}))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
		})
	}
}

func TestMountOnGateDedicatedAdminDoesNotMountOnMain(t *testing.T) {
	t.Parallel()

	cfg := admissionTestConfig()
	cfg.Admin.Enabled = true
	cfg.Admin.Listen.Socket = "/run/admin.sock"
	adminMiddleware := func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	}
	handler := mountOnGate(&cfg, adminMiddleware)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 when dedicated admin listener is configured", rec.Code)
	}
}

func TestMountOnGateSingleListenerPreservesLegacyMount(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.Admin.Enabled = true
	adminMiddleware := func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	}
	handler := mountOnGate(&cfg, adminMiddleware)(http.NotFoundHandler())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 for legacy single-listener in-band admin", rec.Code)
	}
}

func TestListenerAdmissionLegacyModeDoesNotRequireIdentity(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	handler := withListenerAdmission(&cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/_ping", nil).WithContext(context.Background()))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for legacy mode without identity", rec.Code)
	}
}

func TestAllowedProfileSwapIsAtomicForConcurrentInFlightTraffic(t *testing.T) {
	t.Parallel()

	oldCfg := admissionTestConfig()
	entered := make(chan struct{})
	release := make(chan struct{})
	oldHandler := profiledAdmissionHandler(&oldCfg, "ci", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		_, _ = w.Write([]byte("old"))
	}))

	newCfg := admissionTestConfig()
	newCfg.Listeners[0].AllowedProfiles = []string{"ops"}
	newCfg.Listeners[1].AllowedProfiles = []string{"ci"}
	newHandler := profiledAdmissionHandler(&newCfg, "ci", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("new"))
	}))

	swappable := reload.NewSwappableHandler(oldHandler)
	parkedRec := httptest.NewRecorder()
	parkedDone := make(chan struct{})
	go func() {
		defer close(parkedDone)
		req, _ := admissionRequest("ci", inbound.RoleMain)
		swappable.ServeHTTP(parkedRec, req)
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("old-generation request did not enter")
	}

	swappable.Swap(newHandler)
	for _, tc := range []struct {
		listener string
		wantCode int
		wantBody string
	}{
		{listener: "ci", wantCode: http.StatusForbidden},
		{listener: "ops", wantCode: http.StatusOK, wantBody: "new"},
	} {
		req, _ := admissionRequest(tc.listener, inbound.RoleMain)
		rec := httptest.NewRecorder()
		swappable.ServeHTTP(rec, req)
		if rec.Code != tc.wantCode || (tc.wantBody != "" && rec.Body.String() != tc.wantBody) {
			t.Errorf("post-swap listener %s = (%d,%q), want (%d,%q)", tc.listener, rec.Code, rec.Body.String(), tc.wantCode, tc.wantBody)
		}
	}

	close(release)
	<-parkedDone
	if parkedRec.Code != http.StatusOK || parkedRec.Body.String() != "old" {
		t.Fatalf("in-flight old request = (%d,%q), want (200,old)", parkedRec.Code, parkedRec.Body.String())
	}
}
