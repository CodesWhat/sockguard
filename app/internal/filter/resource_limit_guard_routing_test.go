package filter

import (
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
