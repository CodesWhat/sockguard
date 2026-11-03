package filter

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestResourceLimitGuardPassesNonPostAndUnguardedPaths(t *testing.T) {
	opts := ResourceLimitGuardOptions{PolicyConfig: PolicyConfig{
		ContainerUpdate: ContainerUpdateOptions{AllowResourceUpdates: true, RequireMemoryLimit: true},
	}}
	for _, tc := range []struct{ method, target string }{
		{http.MethodGet, "/containers/c/update"},
		{http.MethodPost, "/containers/c/start"},
		{http.MethodPost, "/_ping"},
	} {
		out := runResourceGuardRequest(t, opts, tc.method, tc.target, `{}`, "")
		if out.status != guardedRequestAllowedStatus || out.forwarded != 1 {
			t.Fatalf("%s %s = status %d forwarded %d, want pass-through", tc.method, tc.target, out.status, out.forwarded)
		}
	}
}

func TestResourceLimitGuardProfileResolution(t *testing.T) {
	strict := Policy{PolicyConfig: PolicyConfig{
		ContainerUpdate: ContainerUpdateOptions{AllowResourceUpdates: true, RequireMemoryLimit: true},
	}}
	base := ResourceLimitGuardOptions{
		Profiles: map[string]Policy{"strict": strict},
	}

	t.Run("unresolved resolver result falls back to the default policy", func(t *testing.T) {
		opts := base
		opts.ResolveProfile = func(*http.Request) (string, bool) { return "", false }
		out := runResourceGuardRequest(t, opts, http.MethodPost, "/containers/c/update", `{"Memory":1}`, "")
		if out.status != guardedRequestAllowedStatus || out.forwarded != 1 {
			t.Fatalf("status %d forwarded %d, want default-policy pass-through", out.status, out.forwarded)
		}
	})

	t.Run("a named profile that does not exist is denied", func(t *testing.T) {
		opts := base
		opts.ResolveProfile = func(*http.Request) (string, bool) { return "ghost", true }
		out := runResourceGuardRequest(t, opts, http.MethodPost, "/containers/c/update", `{}`, "")
		if out.status != http.StatusForbidden || out.forwarded != 0 {
			t.Fatalf("status %d forwarded %d, want 403 and no forward", out.status, out.forwarded)
		}
		if out.meta.ReasonCode != reasonCodeClientPolicyProfileUnresolved {
			t.Fatalf("reason code = %q, want %q", out.meta.ReasonCode, reasonCodeClientPolicyProfileUnresolved)
		}
	})

	t.Run("a named profile supplies its own requirements", func(t *testing.T) {
		opts := base
		opts.ResolveProfile = func(*http.Request) (string, bool) { return "strict", true }
		out := runResourceGuardRequest(t, opts, http.MethodPost, "/containers/c/update", `{}`, "")
		// The profile requires a memory limit but this deployment wired no
		// inspector, so the merge cannot be proven and the guard fails closed.
		if out.status == guardedRequestAllowedStatus || out.forwarded != 0 {
			t.Fatalf("status %d forwarded %d, want the strict profile to deny", out.status, out.forwarded)
		}
	})
}

func TestResourceLimitGuardBodyReadFailures(t *testing.T) {
	opts := ResourceLimitGuardOptions{PolicyConfig: PolicyConfig{
		ContainerUpdate: ContainerUpdateOptions{AllowResourceUpdates: true, RequireMemoryLimit: true},
	}}
	oversized := `{"x":"` + strings.Repeat("a", maxContainerUpdateBodyBytes) + `"}`
	out := runResourceGuardRequest(t, opts, http.MethodPost, "/containers/c/update", oversized, "")
	if out.status != http.StatusRequestEntityTooLarge || out.forwarded != 0 {
		t.Fatalf("oversized container update = status %d forwarded %d, want 413", out.status, out.forwarded)
	}
}

func TestResourceLimitGuardServiceBodyFailures(t *testing.T) {
	opts := ResourceLimitGuardOptions{PolicyConfig: PolicyConfig{
		Service: ServiceOptions{RequireCPULimit: true},
	}}
	oversized := `{"x":"` + strings.Repeat("a", maxServiceBodyBytes) + `"}`
	for _, tc := range []struct {
		name       string
		target     string
		body       string
		wantStatus int
	}{
		{"oversized body", "/services/create", oversized, http.StatusRequestEntityTooLarge},
		{"empty body", "/services/create", "", http.StatusBadRequest},
		{"null body", "/services/svc/update?version=7", "null", http.StatusBadRequest},
		{"undecodable body", "/services/create", `{"TaskTemplate":`, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := runResourceGuardRequest(t, opts, http.MethodPost, tc.target, tc.body, "")
			if out.status != tc.wantStatus || out.forwarded != 0 {
				t.Fatalf("status %d forwarded %d, want %d and no forward", out.status, out.forwarded, tc.wantStatus)
			}
		})
	}
}

func TestResourceLimitGuardIdentifierAndVersionParsers(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"/containers/", "/containers/c", "/containers/c/start", "/containers//update"} {
		if _, ok := containerUpdateIdentifier(path); ok {
			t.Fatalf("containerUpdateIdentifier(%q) matched", path)
		}
	}
	for _, path := range []string{"/networks/n/update", "/services/s", "/services/s/rollback", "/services//update"} {
		if _, ok := serviceUpdateIdentifier(path); ok {
			t.Fatalf("serviceUpdateIdentifier(%q) matched", path)
		}
	}
	req := newJSONInspectorFuzzRequest(http.MethodPost, "/services/s/update", "version=notanumber", nil)
	if _, ok := serviceVersionQuery(req); ok {
		t.Fatal("serviceVersionQuery accepted a non-numeric version")
	}
}

func TestDockerInspectorsReportTransportAndStatusFailures(t *testing.T) {
	t.Parallel()
	boom := errors.New("transport down")
	failing := roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, boom })
	notFound := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return dockerInspectResponse(http.StatusNotFound, ``), nil
	})
	serverError := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return dockerInspectResponse(http.StatusInternalServerError, ``), nil
	})
	garbage := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return dockerInspectResponse(http.StatusOK, `{`), nil
	})

	service := func(rt http.RoundTripper) error {
		_, _, err := NewDockerServiceInspectorWithRoundTripper(rt)(context.Background(), "svc")
		return err
	}
	container := func(rt http.RoundTripper) error {
		_, _, err := NewDockerContainerUpdateInspectorWithRoundTripper(rt)(context.Background(), "ctr")
		return err
	}
	if err := service(failing); !errors.Is(err, boom) {
		t.Fatalf("service transport err = %v", err)
	}
	if err := container(failing); !errors.Is(err, boom) {
		t.Fatalf("container transport err = %v", err)
	}
	if _, found, err := NewDockerServiceInspectorWithRoundTripper(notFound)(context.Background(), "svc"); err != nil || found {
		t.Fatalf("service 404 = (found=%v, err=%v), want not found without error", found, err)
	}
	if err := service(serverError); err == nil || !strings.Contains(err.Error(), "returned status 500") {
		t.Fatalf("service 500 err = %v", err)
	}
	if err := service(garbage); err == nil {
		t.Fatal("service undecodable body must error")
	}
	if err := container(garbage); err == nil {
		t.Fatal("container undecodable body must error")
	}
}
