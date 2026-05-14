package reload

import (
	"reflect"
	"sort"
	"testing"

	"github.com/codeswhat/sockguard/internal/config"
)

func TestImmutableDiffEqualConfigs(t *testing.T) {
	a := config.Defaults()
	b := config.Defaults()
	if diff := ImmutableDiff(&a, &b); len(diff) != 0 {
		t.Fatalf("ImmutableDiff(equal) = %v, want empty", diff)
	}
}

func TestImmutableDiffDetectsListenChange(t *testing.T) {
	a := config.Defaults()
	b := a
	b.Listen.Address = "127.0.0.1:9999"
	got := ImmutableDiff(&a, &b)
	if !equalUnordered(got, []string{"listen"}) {
		t.Fatalf("ImmutableDiff(listen.address change) = %v, want [listen]", got)
	}
}

func TestImmutableDiffDetectsUpstreamSocketChange(t *testing.T) {
	a := config.Defaults()
	b := a
	b.Upstream.Socket = "/tmp/other.sock"
	got := ImmutableDiff(&a, &b)
	if !equalUnordered(got, []string{"upstream.socket"}) {
		t.Fatalf("ImmutableDiff(upstream change) = %v, want [upstream.socket]", got)
	}
}

func TestImmutableDiffDetectsLogChange(t *testing.T) {
	a := config.Defaults()
	b := a
	b.Log.Level = "debug"
	got := ImmutableDiff(&a, &b)
	if !equalUnordered(got, []string{"log"}) {
		t.Fatalf("ImmutableDiff(log change) = %v, want [log]", got)
	}
}

func TestImmutableDiffDetectsHealthChange(t *testing.T) {
	a := config.Defaults()
	b := a
	b.Health.Path = "/healthz"
	got := ImmutableDiff(&a, &b)
	if !equalUnordered(got, []string{"health"}) {
		t.Fatalf("ImmutableDiff(health change) = %v, want [health]", got)
	}
}

func TestImmutableDiffDetectsMetricsChange(t *testing.T) {
	a := config.Defaults()
	b := a
	b.Metrics.Enabled = true
	got := ImmutableDiff(&a, &b)
	if !equalUnordered(got, []string{"metrics"}) {
		t.Fatalf("ImmutableDiff(metrics change) = %v, want [metrics]", got)
	}
}

func TestImmutableDiffDetectsAdminChange(t *testing.T) {
	a := config.Defaults()
	b := a
	b.Admin.Enabled = true
	got := ImmutableDiff(&a, &b)
	if !equalUnordered(got, []string{"admin"}) {
		t.Fatalf("ImmutableDiff(admin change) = %v, want [admin]", got)
	}
}

func TestImmutableDiffDetectsPolicyBundleEnableChange(t *testing.T) {
	a := config.Defaults()
	b := a
	b.PolicyBundle.Enabled = true
	got := ImmutableDiff(&a, &b)
	if !equalUnordered(got, []string{"policy_bundle.enabled"}) {
		t.Fatalf("ImmutableDiff(policy_bundle.enabled change) = %v", got)
	}
}

func TestImmutableDiffDetectsPolicyBundleTrustChange(t *testing.T) {
	a := config.Defaults()
	b := a
	b.PolicyBundle.AllowedSigningKeys = []config.PolicyBundleSigningKey{{PEM: "new-key"}}
	got := ImmutableDiff(&a, &b)
	if !equalUnordered(got, []string{"policy_bundle.allowed_signing_keys"}) {
		t.Fatalf("ImmutableDiff(allowed_signing_keys change) = %v", got)
	}
}

func TestImmutableDiffDetectsPolicyBundleKeylessChange(t *testing.T) {
	a := config.Defaults()
	b := a
	b.PolicyBundle.AllowedKeyless = []config.PolicyBundleKeyless{
		{Issuer: "https://example.com", SubjectPattern: ".*"},
	}
	got := ImmutableDiff(&a, &b)
	if !equalUnordered(got, []string{"policy_bundle.allowed_keyless"}) {
		t.Fatalf("ImmutableDiff(allowed_keyless change) = %v", got)
	}
}

func TestImmutableDiffDetectsPolicyBundleRekorChange(t *testing.T) {
	a := config.Defaults()
	b := a
	b.PolicyBundle.RequireRekorInclusion = !a.PolicyBundle.RequireRekorInclusion
	got := ImmutableDiff(&a, &b)
	if !equalUnordered(got, []string{"policy_bundle.require_rekor_inclusion"}) {
		t.Fatalf("ImmutableDiff(require_rekor_inclusion change) = %v", got)
	}
}

func TestImmutableDiffDetectsPolicyBundleTimeoutChange(t *testing.T) {
	a := config.Defaults()
	b := a
	b.PolicyBundle.VerifyTimeout = "42s"
	got := ImmutableDiff(&a, &b)
	if !equalUnordered(got, []string{"policy_bundle.verify_timeout"}) {
		t.Fatalf("ImmutableDiff(verify_timeout change) = %v", got)
	}
}

// SignaturePath is intentionally mutable so an operator can re-sign the
// same YAML without restart.
func TestImmutableDiffIgnoresPolicyBundleSignaturePath(t *testing.T) {
	a := config.Defaults()
	b := a
	b.PolicyBundle.SignaturePath = "/etc/sockguard/cfg.bundle.json.new"
	if diff := ImmutableDiff(&a, &b); len(diff) != 0 {
		t.Fatalf("ImmutableDiff(signature_path change) = %v, want empty (mutable)", diff)
	}
}

// Reloadable fields must not register as a change — these are exactly the
// surface hot-reload exists to update.
func TestImmutableDiffIgnoresReloadableFields(t *testing.T) {
	a := config.Defaults()
	b := a
	b.Rules = append([]config.RuleConfig{}, b.Rules...)
	b.Rules = append(b.Rules, config.RuleConfig{
		Match:  config.MatchConfig{Method: "GET", Path: "/foo"},
		Action: "allow",
	})
	b.Clients.AllowedCIDRs = []string{"10.0.0.0/8"}
	b.Ownership.Owner = "alice"
	b.Response.RedactContainerEnv = !a.Response.RedactContainerEnv
	b.RequestBody.ContainerCreate.AllowPrivileged = !a.RequestBody.ContainerCreate.AllowPrivileged
	b.InsecureAllowBodyBlindWrites = !a.InsecureAllowBodyBlindWrites

	if diff := ImmutableDiff(&a, &b); len(diff) != 0 {
		t.Fatalf("ImmutableDiff(reloadable-only change) = %v, want empty", diff)
	}
}

func TestImmutableDiffMultipleChanges(t *testing.T) {
	a := config.Defaults()
	b := a
	b.Listen.Address = "0.0.0.0:2375"
	b.Log.Level = "debug"
	b.Admin.Enabled = true

	got := ImmutableDiff(&a, &b)
	want := []string{"listen", "log", "admin"}
	if !equalUnordered(got, want) {
		t.Fatalf("ImmutableDiff(multi) = %v, want %v", got, want)
	}
}

func TestImmutableDiffNilInputs(t *testing.T) {
	a := config.Defaults()
	if diff := ImmutableDiff(nil, &a); len(diff) != 0 {
		t.Fatalf("ImmutableDiff(nil, cfg) = %v, want empty", diff)
	}
	if diff := ImmutableDiff(&a, nil); len(diff) != 0 {
		t.Fatalf("ImmutableDiff(cfg, nil) = %v, want empty", diff)
	}
}

func equalUnordered(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]string(nil), a...)
	bc := append([]string(nil), b...)
	sort.Strings(ac)
	sort.Strings(bc)
	return reflect.DeepEqual(ac, bc)
}
